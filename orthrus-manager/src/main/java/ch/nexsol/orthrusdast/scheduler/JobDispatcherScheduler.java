/*
 * Copyright 2014-2024 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package ch.nexsol.orthrusdast.scheduler;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import ch.nexsol.orthrusdast.config.OrthrusProperties;
import ch.nexsol.orthrusdast.engine.JobOrchestratorService;
import ch.nexsol.orthrusdast.entity.ScanTaskEntity;
import ch.nexsol.orthrusdast.entity.SlaveNodeEntity;
import ch.nexsol.orthrusdast.model.JobStatus;
import ch.nexsol.orthrusdast.model.NodeStatus;
import ch.nexsol.orthrusdast.repository.ScanJobRepository;
import ch.nexsol.orthrusdast.repository.ScanTaskRepository;
import ch.nexsol.orthrusdast.repository.SlaveNodeRepository;
import ch.nexsol.orthrusdast.sse.JobEvent;
import ch.nexsol.orthrusdast.sse.JobEventPublisher;

@Component
@EnableScheduling
public class JobDispatcherScheduler {

	private static final Logger log = LoggerFactory.getLogger(JobDispatcherScheduler.class);

	private static final int DEFAULT_MAX_CONCURRENT_SCANS = 10;

	private static final Duration GLOBAL_JOB_TIMEOUT = Duration.ofHours(4);

	private final ScanJobRepository scanJobRepository;

	private final ScanTaskRepository scanTaskRepository;

	private final SlaveNodeRepository slaveNodeRepository;

	private final WebClient webClient;

	private final OrthrusProperties orthrusProperties;

	private final JobEventPublisher jobEventPublisher;

	private final JobOrchestratorService jobOrchestratorService;

	private final AtomicBoolean dispatchInFlight = new AtomicBoolean();

	private final AtomicBoolean healthCheckInFlight = new AtomicBoolean();

	public JobDispatcherScheduler(ScanJobRepository scanJobRepository, ScanTaskRepository scanTaskRepository,
			SlaveNodeRepository slaveNodeRepository, OrthrusProperties orthrusProperties,
			JobEventPublisher jobEventPublisher, JobOrchestratorService jobOrchestratorService,
			WebClient.Builder webClientBuilder) {
		this.scanJobRepository = scanJobRepository;
		this.scanTaskRepository = scanTaskRepository;
		this.slaveNodeRepository = slaveNodeRepository;
		this.webClient = webClientBuilder.build();
		this.orthrusProperties = orthrusProperties;
		this.jobEventPublisher = jobEventPublisher;
		this.jobOrchestratorService = jobOrchestratorService;
	}

	/**
	 * Runs one dispatch cycle: split queued jobs into tasks, then place those tasks on
	 * nodes. Cycles never overlap; a tick that arrives while one is still running is
	 * skipped.
	 */
	@Scheduled(fixedDelay = 5000)
	public void dispatchPendingJobs() {
		runOneAtATime(this.dispatchInFlight, "Dispatch cycle",
				() -> this.jobOrchestratorService.processPendingJobs().then(Mono.defer(this::placePendingTasks)));
	}

	/**
	 * Runs a scheduled cycle, skipping the tick if the previous run has not finished.
	 * {@code fixedDelay} counts from when the scheduled method returns, and these methods
	 * return as soon as their pipeline is subscribed.
	 * @param guard tracks whether this cycle is already running
	 * @param cycle the cycle name, for logging
	 * @param work builds the pipeline, on demand
	 */
	private void runOneAtATime(AtomicBoolean guard, String cycle, Supplier<Mono<Void>> work) {
		if (!guard.compareAndSet(false, true)) {
			log.debug("{} is still running; skipping this tick.", cycle);
			return;
		}
		Mono.defer(work)
			.doFinally((signal) -> guard.set(false))
			.subscribe(null, (e) -> log.error("{} failed", cycle, e));
	}

	/**
	 * Places pending tasks one at a time, so each quota check sees the placements before
	 * it.
	 * @return completion signal
	 */
	private Mono<Void> placePendingTasks() {
		return this.scanTaskRepository.findByStatus(JobStatus.PENDING)
			.concatMap((task) -> selectSlaveFor(task).flatMap((slave) -> dispatchTaskToSlave(task, slave)))
			.then();
	}

	/**
	 * Picks the node that should run a task, preferring the one already running the same
	 * job so its cached discovery is reused.
	 * @param task the task waiting to be placed
	 * @return the chosen node, or empty when no node can take it right now
	 */
	private Mono<SlaveNodeEntity> selectSlaveFor(ScanTaskEntity task) {
		return liveSlaves().collectList().flatMap((live) -> {
			if (live.isEmpty()) {
				// The fleet is down; leave the task pending and retry on the next tick.
				return Mono.empty();
			}

			List<SlaveNodeEntity> capable = live.stream()
				.filter((slave) -> slave.getCapabilities() != null && slave.getCapabilities().contains(task.getPhase()))
				.toList();

			if (capable.isEmpty()) {
				// No node advertises this phase, so the task can never run.
				return this.jobOrchestratorService
					.onTaskUnsupported(task.getId(), "no live node advertises phase " + task.getPhase())
					.then(Mono.empty());
			}

			return Flux.fromIterable(capable)
				.filterWhen(this::hasFreeSlot)
				.collectList()
				.flatMap((available) -> pickPreferred(task.getScanJobId(), available));
		});
	}

	private Flux<SlaveNodeEntity> liveSlaves() {
		Instant aliveSince = Instant.now().minusSeconds(this.orthrusProperties.getMaster().getSlaveTimeoutSeconds());
		return this.slaveNodeRepository.findAll()
			.filter((slave) -> Boolean.TRUE.equals(slave.getIsActive()))
			.filter((slave) -> slave.getStatus() != NodeStatus.OFFLINE)
			.filter((slave) -> slave.getLastSeenAt() != null && slave.getLastSeenAt().isAfter(aliveSince));
	}

	private Mono<Boolean> hasFreeSlot(SlaveNodeEntity slave) {
		return this.scanTaskRepository.countByAssignedSlaveIdAndStatus(slave.getId(), JobStatus.RUNNING)
			.map((running) -> running < maxConcurrentScans(slave));
	}

	/**
	 * Prefers the node already running a task of the same job, falling back to any free
	 * node.
	 * @param jobId the job being scheduled
	 * @param available the nodes with a free slot
	 * @return the chosen node, or empty when none is free
	 */
	private Mono<SlaveNodeEntity> pickPreferred(Long jobId, List<SlaveNodeEntity> available) {
		if (available.isEmpty()) {
			return Mono.empty();
		}
		return slaveAlreadyRunningJob(jobId)
			.flatMap((preferredId) -> Mono
				.justOrEmpty(available.stream().filter((slave) -> slave.getId().equals(preferredId)).findFirst()))
			.switchIfEmpty(Mono.just(available.get(0)));
	}

	/**
	 * @param jobId the job being scheduled
	 * @return the node already running one of this job's tasks, if any
	 */
	private Mono<String> slaveAlreadyRunningJob(Long jobId) {
		return this.scanTaskRepository.findByScanJobId(jobId)
			.filter((sibling) -> sibling.getAssignedSlaveId() != null && sibling.getStatus() == JobStatus.RUNNING)
			.next()
			.map(ScanTaskEntity::getAssignedSlaveId);
	}

	private int maxConcurrentScans(SlaveNodeEntity slave) {
		return (slave.getMaxConcurrentScans() != null && slave.getMaxConcurrentScans() > 0)
				? slave.getMaxConcurrentScans() : DEFAULT_MAX_CONCURRENT_SCANS;
	}

	@Scheduled(fixedDelay = 10000)
	public void monitorSlavesHealth() {
		runOneAtATime(this.healthCheckInFlight, "Health check cycle", this::pingSlaves);
	}

	private Mono<Void> pingSlaves() {
		return this.slaveNodeRepository.findAll()
			.flatMap((slave) -> this.webClient.get()
				.uri(slave.getUrl() + "/api/v1/slave/capabilities")
				.retrieve()
				.bodyToMono(Void.class)
				.timeout(Duration.ofSeconds(3))
				.thenReturn(true)
				.onErrorResume((e) -> {
					log.warn("Ping failed to {}: {}", slave.getUrl(), e.getMessage());
					return Mono.just(false);
				})
				.flatMap((isUp) -> {
					if (!isUp && slave.getStatus() != NodeStatus.OFFLINE) {
						log.warn("Slave {} is unreachable. Marking as OFFLINE.", slave.getId());
						return this.slaveNodeRepository
							.updateSlaveNodeStatusAndLastSeenAt(slave.getId(), NodeStatus.OFFLINE.name(),
									slave.getLastSeenAt())
							.then(this.jobOrchestratorService.recoverTasksOfSlave(slave.getId(),
									"Slave node crashed or disconnected"));
					}
					// A node that comes back announces itself through its own heartbeat.
					return Mono.empty();
				}))
			.then();
	}

	@Scheduled(fixedDelay = 60000)
	public void monitorGlobalTimeouts() {
		Instant cutoff = Instant.now().minus(GLOBAL_JOB_TIMEOUT);
		this.scanJobRepository.findByStatusAndStartedAtBefore(JobStatus.RUNNING, cutoff)
			.flatMap((job) -> this.scanJobRepository.finishJob(job.getId(), JobStatus.FAILED.name(), Instant.now())
				.defaultIfEmpty(0)
				.doOnNext((finished) -> {
					if (finished == 1) {
						log.warn("Job {} has exceeded the global {}h timeout. Marking as FAILED.", job.getId(),
								GLOBAL_JOB_TIMEOUT.toHours());
						this.jobEventPublisher.emit(job.getId(),
								JobEvent.failed(job.getId(), job.getTarget(), "Global Timeout Exceeded (4h)"));
						this.jobEventPublisher.complete(job.getId());
					}
				}))
			.subscribe(null, (e) -> log.error("Global timeout sweep failed", e));
	}

	@Scheduled(fixedDelay = 60000)
	public void cleanupOfflineSlaves() {
		Instant cutoff = Instant.now()
			.minus(Duration.ofMinutes(this.orthrusProperties.getMaster().getOfflineSlaveDeletionMinutes()));
		this.slaveNodeRepository.deleteOfflineSlaves(cutoff)
			.filter((count) -> count > 0)
			.doOnNext((count) -> log.info("Deleted {} offline slave nodes.", count))
			.subscribe(null, (e) -> log.error("Offline slave cleanup failed", e));
	}

	private Mono<Void> dispatchTaskToSlave(ScanTaskEntity task, SlaveNodeEntity slave) {
		Instant startedAt = Instant.now();

		return this.scanTaskRepository.claimForDispatch(task.getId(), slave.getId(), startedAt)
			.defaultIfEmpty(0)
			.filter((claimed) -> {
				if (claimed != 1) {
					log.debug("Task {} was already claimed by another dispatch cycle; skipping.", task.getId());
					return false;
				}
				return true;
			})
			.flatMap((claimed) -> sendClaimedTask(task, slave, startedAt))
			.then();
	}

	private Mono<Void> sendClaimedTask(ScanTaskEntity task, SlaveNodeEntity slave, Instant startedAt) {
		task.setStatus(JobStatus.RUNNING);
		task.setAssignedSlaveId(slave.getId());
		task.setStartedAt(startedAt);

		return this.scanJobRepository.findById(task.getScanJobId()).flatMap((job) -> {
			ScanTaskRequest payload = new ScanTaskRequest(task.getId(), job.getId(), task.getPhase(),
					job.getDiscovererId(), job.getTarget(), job.getScanConfigurationJson());

			// Column-scoped update: results stream in concurrently and a whole-row write
			// would roll back the counters.
			Mono<?> recordOwner = slave.getId().equals(job.getAssignedSlaveId()) ? Mono.empty()
					: this.scanJobRepository.assignSlave(job.getId(), slave.getId());

			return recordOwner.then(this.webClient.post()
				.uri(slave.getUrl() + "/api/v1/slave/tasks")
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue(payload)
				.retrieve()
				.bodyToMono(Void.class)
				.timeout(Duration.ofMillis(this.orthrusProperties.getMaster().getDispatchTimeoutMs()))
				.onErrorResume((e) -> {
					log.error("Dispatch of task {} to {} failed: {}", task.getId(), slave.getUrl(), e.getMessage());
					return this.jobOrchestratorService.onTaskFailed(task.getId(), "Dispatch failed");
				}));
		}).then();
	}

	record ScanTaskRequest(Long taskId, Long jobId, String phase, String discovererId, String target,
			String scanConfigurationJson) {
	}

}

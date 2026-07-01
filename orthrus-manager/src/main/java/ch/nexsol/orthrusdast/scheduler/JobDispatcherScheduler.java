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

import org.springframework.http.MediaType;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import ch.nexsol.orthrusdast.config.OrthrusProperties;
import ch.nexsol.orthrusdast.entity.SlaveNodeEntity;
import ch.nexsol.orthrusdast.model.JobStatus;
import ch.nexsol.orthrusdast.model.NodeStatus;
import ch.nexsol.orthrusdast.repository.ScanJobRepository;
import ch.nexsol.orthrusdast.repository.SlaveNodeRepository;
import ch.nexsol.orthrusdast.sse.JobEvent;
import ch.nexsol.orthrusdast.sse.JobEventPublisher;

@Component
@EnableScheduling
public class JobDispatcherScheduler {

	private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(JobDispatcherScheduler.class);

	private final ScanJobRepository scanJobRepository;

	private final ch.nexsol.orthrusdast.repository.ScanTaskRepository scanTaskRepository;

	private final SlaveNodeRepository slaveNodeRepository;

	private final WebClient webClient;

	private final OrthrusProperties orthrusProperties;

	private final JobEventPublisher jobEventPublisher;

	private final ch.nexsol.orthrusdast.engine.JobOrchestratorService jobOrchestratorService;

	public JobDispatcherScheduler(ScanJobRepository scanJobRepository,
			ch.nexsol.orthrusdast.repository.ScanTaskRepository scanTaskRepository,
			SlaveNodeRepository slaveNodeRepository, OrthrusProperties orthrusProperties,
			JobEventPublisher jobEventPublisher,
			ch.nexsol.orthrusdast.engine.JobOrchestratorService jobOrchestratorService,
			WebClient.Builder webClientBuilder) {
		this.scanJobRepository = scanJobRepository;
		this.scanTaskRepository = scanTaskRepository;
		this.slaveNodeRepository = slaveNodeRepository;
		this.webClient = webClientBuilder.build();
		this.orthrusProperties = orthrusProperties;
		this.jobEventPublisher = jobEventPublisher;
		this.jobOrchestratorService = jobOrchestratorService;
	}

	@Scheduled(fixedDelay = 5000)
	public void dispatchPendingJobs() {
		// Orchestrate jobs into tasks
		jobOrchestratorService.processPendingJobs().subscribe();

		// 1. Find all PENDING tasks and process them sequentially
		scanTaskRepository.findByStatus(JobStatus.PENDING).concatMap((task) -> {
			return slaveNodeRepository.findAll()
				.filter((slave) -> Boolean.TRUE.equals(slave.getIsActive()))
				.filter((slave) -> slave.getStatus() != NodeStatus.OFFLINE)
				.filter((slave) -> slave.getLastSeenAt().isAfter(Instant.now().minusSeconds(30)))
				.collectList()
				.flatMap((slaves) -> {
					if (slaves.isEmpty()) {
						return Mono.empty();
					}

					boolean anyCapable = slaves.stream()
						.anyMatch((s) -> s.getCapabilities() != null && s.getCapabilities().contains(task.getPhase()));

					if (!anyCapable) {
						log.info("No capable slave found for task {} phase {} among {} active slaves. Auto-completing.",
								task.getId(), task.getPhase(), slaves.size());
						return jobOrchestratorService.onScanTaskComplete(task.getId(), 0, 0);
					}

					return Flux.fromIterable(slaves)
						.filter((slave) -> slave.getCapabilities() != null
								&& slave.getCapabilities().contains(task.getPhase()))
						.filterWhen((slave) -> scanTaskRepository
							.countByAssignedSlaveIdAndStatus(slave.getId(), JobStatus.RUNNING)
							.map((count) -> {
								int maxScans = (slave.getMaxConcurrentScans() != null
										&& slave.getMaxConcurrentScans() > 0) ? slave.getMaxConcurrentScans() : 10;
								return count < maxScans;
							}))
						.next()
						.flatMap((slave) -> dispatchTaskToSlave(task, slave));
				});
		}).subscribe();
	}

	@Scheduled(fixedDelay = 10000)
	public void monitorSlavesHealth() {
		slaveNodeRepository.findAll().flatMap((slave) -> {
			return webClient.get()
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
						return slaveNodeRepository
							.updateSlaveNodeStatusAndLastSeenAt(slave.getId(), NodeStatus.OFFLINE.name(),
									slave.getLastSeenAt())
							.flatMap((r) -> failZombieScansForSlave(slave.getId()))
							.doOnSuccess(
									(r) -> log.info("Slave {} marked OFFLINE and zombie scans failed.", slave.getId()));
					}
					else if (isUp && slave.getStatus() == NodeStatus.OFFLINE) {
						log.info("Slave {} is back online. Marking as IDLE.", slave.getId());
						return slaveNodeRepository
							.updateSlaveNodeStatusAndLastSeenAt(slave.getId(), NodeStatus.IDLE.name(), Instant.now())
							.doOnSuccess((r) -> log.debug("Rows updated to IDLE: {}", r));
					}
					return Mono.empty();
				});
		}).subscribe();
	}

	@Scheduled(fixedDelay = 60000)
	public void monitorGlobalTimeouts() {
		// Find jobs that have been RUNNING for more than 4 hours
		Instant fourHoursAgo = Instant.now().minus(Duration.ofHours(4));
		scanJobRepository.findByStatusAndStartedAtBefore(JobStatus.RUNNING, fourHoursAgo).flatMap((job) -> {
			log.warn("Job {} has exceeded the global 4-hour timeout. Marking as FAILED.", job.getId());
			job.setStatus(JobStatus.FAILED);
			return scanJobRepository.save(job)
				.doOnSuccess((j) -> jobEventPublisher.emit(j.getId(),
						JobEvent.failed(j.getId(), j.getTarget(), "Global Timeout Exceeded (4h)")));
		}).subscribe();
	}

	private Mono<Void> failZombieScansForSlave(String slaveId) {
		return scanTaskRepository.findByAssignedSlaveIdAndStatus(slaveId, JobStatus.RUNNING).flatMap((task) -> {
			int retryCount = task.getRetryCount() != null ? task.getRetryCount() : 0;
			if (retryCount < 3) {
				log.info("Retrying zombie task {} (Attempt {}) because assigned slave {} went OFFLINE.", task.getId(),
						(retryCount + 1), slaveId);
				task.setRetryCount(retryCount + 1);
				task.setStatus(JobStatus.PENDING);
				task.setAssignedSlaveId(null);
				task.setStartedAt(null);
				return scanTaskRepository.save(task).then();
			}
			else {
				log.warn("Failing zombie task {} because assigned slave {} went OFFLINE.", task.getId(), slaveId);
				task.setStatus(JobStatus.FAILED);
				return scanTaskRepository.save(task)
					.flatMap((t) -> jobOrchestratorService.onTaskFailed(t.getId(),
							"Slave node crashed or disconnected"));
			}
		}).then();
	}

	@Scheduled(fixedDelay = 60000)
	public void cleanupOfflineSlaves() {
		Instant cutoff = Instant.now()
			.minus(Duration.ofMinutes(orthrusProperties.getMaster().getOfflineSlaveDeletionMinutes()));
		slaveNodeRepository.deleteOfflineSlaves(cutoff)
			.filter((count) -> count > 0)
			.doOnNext((count) -> log.info("Deleted {} offline slave nodes.", count))
			.subscribe();
	}

	record ScanTaskRequest(Long taskId, Long jobId, String phase, String discovererId, String target,
			String scanConfigurationJson) {
	}

	private Mono<Void> dispatchTaskToSlave(ch.nexsol.orthrusdast.entity.ScanTaskEntity task, SlaveNodeEntity slave) {
		return scanTaskRepository.countByAssignedSlaveIdAndStatus(slave.getId(), JobStatus.RUNNING)
			.flatMap((runningCount) -> {
				long newCount = runningCount + 1;
				int maxScans = (slave.getMaxConcurrentScans() != null && slave.getMaxConcurrentScans() > 0)
						? slave.getMaxConcurrentScans() : 10;
				if (newCount >= maxScans) {
					slave.setStatus(NodeStatus.BUSY);
				}
				else {
					slave.setStatus(NodeStatus.IDLE);
				}
				return slaveNodeRepository.updateSlaveNodeStatusAndLastSeenAt(slave.getId(), slave.getStatus().name(),
						slave.getLastSeenAt());
			})
			.flatMap((rows) -> {
				task.setStatus(JobStatus.RUNNING);
				task.setAssignedSlaveId(slave.getId());
				task.setStartedAt(Instant.now());
				return scanTaskRepository.save(task);
			})
			.flatMap((t) -> scanJobRepository.findById(t.getScanJobId()).flatMap((job) -> {
				ScanTaskRequest payload = new ScanTaskRequest(t.getId(), job.getId(), t.getPhase(),
						job.getDiscovererId(), job.getTarget(), job.getScanConfigurationJson());

				return webClient.post()
					.uri(slave.getUrl() + "/api/v1/slave/tasks")
					.contentType(MediaType.APPLICATION_JSON)
					.bodyValue(payload)
					.retrieve()
					.bodyToMono(Void.class)
					.onErrorResume((e) -> {
						log.error("Dispatch failed to {}: {}", slave.getUrl(), e.getMessage());
						t.setStatus(JobStatus.FAILED);
						return scanTaskRepository.save(t)
							.flatMap((saved) -> jobOrchestratorService.onTaskFailed(t.getId(), "Dispatch failed"))
							.then(Mono.empty());
					});
			}));
	}

}

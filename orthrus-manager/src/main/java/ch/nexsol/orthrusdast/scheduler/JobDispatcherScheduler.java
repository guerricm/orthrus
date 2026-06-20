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
import reactor.core.publisher.Mono;

import ch.nexsol.orthrusdast.config.OrthrusProperties;
import ch.nexsol.orthrusdast.entity.ScanJobEntity;
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
		scanTaskRepository.findByStatus(JobStatus.PENDING).concatMap((task) ->
		// 2. Find an eligible slave for each task
		slaveNodeRepository.findAll()
			.filter((slave) -> Boolean.TRUE.equals(slave.getIsActive()))
			.filter((slave) -> slave.getStatus() != NodeStatus.OFFLINE)
			.filter((slave) -> slave.getLastSeenAt().isAfter(Instant.now().minusSeconds(30)))
			.filterWhen((slave) -> scanTaskRepository.countByAssignedSlaveIdAndStatus(slave.getId(), JobStatus.RUNNING)
				.map((count) -> count < slave.getMaxConcurrentScans()))
			.next()
			.flatMap((slave) -> dispatchTaskToSlave(task, slave))).subscribe();
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
					System.err.println("Ping failed to " + slave.getUrl() + ": " + e.getMessage());
					return Mono.just(false);
				})
				.flatMap((isUp) -> {
					if (!isUp && slave.getStatus() != NodeStatus.OFFLINE) {
						System.out.println("Slave " + slave.getId() + " is unreachable. Marking as OFFLINE.");
						return slaveNodeRepository
							.updateSlaveNodeStatusAndLastSeenAt(slave.getId(), NodeStatus.OFFLINE.name(),
									slave.getLastSeenAt())
							.flatMap((r) -> failZombieScansForSlave(slave.getId()))
							.doOnSuccess((r) -> System.out
								.println("Slave " + slave.getId() + " marked OFFLINE and zombie scans failed."));
					}
					else if (isUp && slave.getStatus() == NodeStatus.OFFLINE) {
						System.out.println("Slave " + slave.getId() + " is back online. Marking as IDLE.");
						return slaveNodeRepository
							.updateSlaveNodeStatusAndLastSeenAt(slave.getId(), NodeStatus.IDLE.name(), Instant.now())
							.doOnSuccess((r) -> System.out.println("Rows updated to IDLE: " + r));
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
			System.out.println("Job " + job.getId() + " has exceeded the global 4-hour timeout. Marking as FAILED.");
			job.setStatus(JobStatus.FAILED);
			return scanJobRepository.save(job)
				.doOnSuccess((j) -> jobEventPublisher.emit(j.getId(),
						JobEvent.failed(j.getId(), j.getTarget(), "Global Timeout Exceeded (4h)")));
		}).subscribe();
	}

	private Mono<Void> failZombieScansForSlave(String slaveId) {
		return scanTaskRepository.findByAssignedSlaveIdAndStatus(slaveId, JobStatus.RUNNING).flatMap((task) -> {
			System.out.println(
					"Failing zombie task " + task.getId() + " because assigned slave " + slaveId + " went OFFLINE.");
			task.setStatus(JobStatus.FAILED);
			return scanTaskRepository.save(task)
				.flatMap((t) -> jobOrchestratorService.onTaskFailed(t.getId(), "Slave node crashed or disconnected"));
		}).then();
	}

	record ScanTaskRequest(Long taskId, Long jobId, String phase, String discovererId, String target,
			String scanConfigurationJson) {
	}

	private Mono<Void> dispatchTaskToSlave(ch.nexsol.orthrusdast.entity.ScanTaskEntity task, SlaveNodeEntity slave) {
		return scanTaskRepository.countByAssignedSlaveIdAndStatus(slave.getId(), JobStatus.RUNNING)
			.flatMap((runningCount) -> {
				long newCount = runningCount + 1;
				if (newCount >= slave.getMaxConcurrentScans()) {
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
						System.err.println("Dispatch failed to " + slave.getUrl() + ": " + e.getMessage());
						t.setStatus(JobStatus.FAILED);
						return scanTaskRepository.save(t)
							.flatMap((saved) -> jobOrchestratorService.onTaskFailed(t.getId(), "Dispatch failed"))
							.then(Mono.empty());
					});
			}));
	}

}

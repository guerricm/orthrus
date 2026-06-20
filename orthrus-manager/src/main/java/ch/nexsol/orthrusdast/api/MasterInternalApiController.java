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

package ch.nexsol.orthrusdast.api;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.codec.ServerSentEvent;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import ch.nexsol.orthrusdast.engine.ScanResultService;
import ch.nexsol.orthrusdast.entity.ScanJobEntity;
import ch.nexsol.orthrusdast.entity.SlaveNodeEntity;
import ch.nexsol.orthrusdast.model.JobStatus;
import ch.nexsol.orthrusdast.model.NodeStatus;
import ch.nexsol.orthrusdast.model.RiskLevel;
import ch.nexsol.orthrusdast.model.ScanAttempt;
import ch.nexsol.orthrusdast.model.ScanResult;
import ch.nexsol.orthrusdast.repository.ScanJobRepository;
import ch.nexsol.orthrusdast.repository.SlaveNodeRepository;
import ch.nexsol.orthrusdast.sse.JobEvent;
import ch.nexsol.orthrusdast.sse.JobEventPublisher;

@RestController
@RequestMapping("/api/internal")
public class MasterInternalApiController {

	private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(MasterInternalApiController.class);

	private final SlaveNodeRepository slaveNodeRepository;

	private final ScanJobRepository scanJobRepository;

	private final ScanResultService scanResultService;

	private final JobEventPublisher jobEventPublisher;

	private final ch.nexsol.orthrusdast.engine.JobOrchestratorService jobOrchestratorService;

	private final ch.nexsol.orthrusdast.repository.ScanTaskRepository scanTaskRepository;

	public MasterInternalApiController(SlaveNodeRepository slaveNodeRepository, ScanJobRepository scanJobRepository,
			ScanResultService scanResultService, JobEventPublisher jobEventPublisher,
			ch.nexsol.orthrusdast.engine.JobOrchestratorService jobOrchestratorService,
			ch.nexsol.orthrusdast.repository.ScanTaskRepository scanTaskRepository) {
		this.slaveNodeRepository = slaveNodeRepository;
		this.scanJobRepository = scanJobRepository;
		this.scanResultService = scanResultService;
		this.jobEventPublisher = jobEventPublisher;
		this.jobOrchestratorService = jobOrchestratorService;
		this.scanTaskRepository = scanTaskRepository;
	}

	/**
	 * Called by Slave to register its presence.
	 */
	@PostMapping("/slaves/register")
	public Mono<ResponseEntity<SlaveNodeEntity>> registerSlave(@RequestBody SlaveRegistrationRequest request) {
		SlaveNodeEntity node = new SlaveNodeEntity(request.id(), request.url(), NodeStatus.IDLE,
				request.capabilities());
		return slaveNodeRepository.findById(node.getId())
			.flatMap((existing) -> slaveNodeRepository
				.updateSlaveNodeUrlStatusCapabilitiesAndLastSeenAt(node.getId(), node.getUrl(), node.getStatus().name(),
						node.getCapabilities(), node.getLastSeenAt())
				.then(failZombieScansForSlave(node.getId()))
				.thenReturn(ResponseEntity.ok(node)))
			.switchIfEmpty(
					Mono.defer(() -> slaveNodeRepository
						.insertSlaveNode(node.getId(), node.getUrl(), node.getStatus(), node.getCapabilities(),
								node.getLastSeenAt())
						.thenReturn(ResponseEntity.ok(node))));
	}

	private Mono<Void> failZombieScansForSlave(String slaveId) {
		return scanJobRepository.findByAssignedSlaveIdAndStatus(slaveId, JobStatus.RUNNING).flatMap((job) -> {
			int retryCount = job.getRetryCount() != null ? job.getRetryCount() : 0;
			if (retryCount < 3) {
				log.info("Retrying zombie job {} (Attempt {}) because slave {} re-registered.", job.getId(),
						(retryCount + 1), slaveId);
				job.setRetryCount(retryCount + 1);
				job.setStatus(JobStatus.PENDING);
				job.setAssignedSlaveId(null);
				job.setStartedAt(null);
				return scanJobRepository.save(job).then();
			}
			else {
				log.warn("Failing zombie job {} because slave {} re-registered.", job.getId(), slaveId);
				job.setStatus(JobStatus.FAILED);
				return scanJobRepository.save(job)
					.doOnSuccess((j) -> jobEventPublisher.emit(j.getId(),
							JobEvent.failed(j.getId(), j.getTarget(), "Slave node restarted")))
					.then();
			}
		}).then();
	}

	/**
	 * Called by Slave to send a heartbeat.
	 */
	@PostMapping("/slaves/{id}/heartbeat")
	public Mono<ResponseEntity<Void>> slaveHeartbeat(@PathVariable String id,
			@RequestParam(defaultValue = "IDLE") NodeStatus status, @RequestParam(required = false) String url) {

		Mono<Integer> updateMono;
		if (url != null && !url.trim().isEmpty()) {
			updateMono = slaveNodeRepository.updateSlaveNodeUrlStatusAndLastSeenAt(id, url, status.name(),
					Instant.now());
		}
		else {
			updateMono = slaveNodeRepository.updateSlaveNodeStatusAndLastSeenAt(id, status.name(), Instant.now());
		}

		return updateMono.flatMap((rows) -> {
			if (rows == 0) {
				return Mono.just(ResponseEntity.notFound().build());
			}
			return Mono.just(ResponseEntity.ok().<Void>build());
		});
	}

	/**
	 * Called by Slave to post a batch of attempts.
	 */
	@PostMapping("/jobs/{id}/attempts")
	public Mono<ResponseEntity<Void>> postJobAttemptsBatch(@PathVariable Long id,
			@RequestBody List<ScanAttempt> batch) {
		return scanJobRepository.findById(id).flatMap((job) -> {
			Mono<Void> ensureResultExists = Mono.empty();
			if (job.getResultId() == null) {
				job.setResultId(UUID.randomUUID().toString());
				ensureResultExists = scanResultService.createPlaceholderResult(job.getResultId(), job.getTarget(),
						job.getCreatedAt() != null ? job.getCreatedAt() : Instant.now());
			}

			int vulnsInBatch = 0;
			for (ScanAttempt attempt : batch) {
				if (attempt.vulnerabilities() != null) {
					vulnsInBatch += attempt.vulnerabilities().size();
				}
			}

			job.setTestsCount((job.getTestsCount() != null ? job.getTestsCount() : 0) + batch.size());
			job.setVulnsCount((job.getVulnsCount() != null ? job.getVulnsCount() : 0) + vulnsInBatch);

			return ensureResultExists.then(scanResultService.saveBatch(job.getResultId(), batch))
				.then(scanJobRepository.save(job))
				.thenReturn(ResponseEntity.ok().<Void>build());
		}).defaultIfEmpty(ResponseEntity.notFound().build());
	}

	record CompleteJobRequest(Instant startTime, Instant endTime) {
	}

	/**
	 * Called by Slave to mark job as complete.
	 */
	@PostMapping("/jobs/{id}/complete")
	public Mono<ResponseEntity<Void>> postJobComplete(@PathVariable Long id, @RequestBody CompleteJobRequest request) {
		return scanJobRepository.findById(id).flatMap((job) -> {
			job.setStatus(JobStatus.COMPLETED);
			job.setCompletedAt(request.endTime() != null ? request.endTime() : Instant.now());

			Mono<Void> ensureResultExists = Mono.empty();
			if (job.getResultId() == null) {
				job.setResultId(UUID.randomUUID().toString());
				ensureResultExists = scanResultService.createPlaceholderResult(job.getResultId(), job.getTarget(),
						request.startTime() != null ? request.startTime() : Instant.now());
			}

			int testsCount = job.getTestsCount() != null ? job.getTestsCount() : 0;

			return ensureResultExists
				.then(scanResultService.finalizeJobResult(job.getResultId(), job.getTarget(), request.startTime(),
						job.getCompletedAt(), testsCount))
				.flatMap((result) -> scanJobRepository.save(job).doOnSuccess((j) -> {
					long critical = result.riskSummary().getOrDefault(RiskLevel.CRITICAL, 0L);
					long high = result.riskSummary().getOrDefault(RiskLevel.HIGH, 0L);
					long medium = result.riskSummary().getOrDefault(RiskLevel.MEDIUM, 0L);
					long low = result.riskSummary().getOrDefault(RiskLevel.LOW, 0L);
					String grade = "A";
					if (critical > 0)
						grade = "F";
					else if (high > 0)
						grade = "D";
					else if (medium > 0)
						grade = "C";
					else if (low > 0)
						grade = "B";

					long info = result.riskSummary().getOrDefault(RiskLevel.INFO, 0L);

					jobEventPublisher.emit(id,
							JobEvent.completed(id, job.getTarget(), result.id(), grade, result.vulnerabilities().size(),
									critical, high, medium, low, info, result.operationsScanned()));
					jobEventPublisher.complete(id);

					if (job.getAssignedSlaveId() != null) {
						slaveNodeRepository.findById(job.getAssignedSlaveId())
							.flatMap((slave) -> scanJobRepository
								.countByAssignedSlaveIdAndStatus(slave.getId(), JobStatus.RUNNING)
								.flatMap((runningCount) -> {
									int maxScans = (slave.getMaxConcurrentScans() != null
											&& slave.getMaxConcurrentScans() > 0) ? slave.getMaxConcurrentScans() : 10;
									if (runningCount < maxScans) {
										return slaveNodeRepository.updateSlaveNodeStatusAndLastSeenAt(slave.getId(),
												NodeStatus.IDLE.name(), slave.getLastSeenAt());
									}
									return Mono.empty();
								}))
							.subscribe();
					}
				}));
		}).map((j) -> ResponseEntity.ok().<Void>build()).defaultIfEmpty(ResponseEntity.notFound().build());
	}

	record FailJobRequest(String reason) {
	}

	@PostMapping("/jobs/{id}/fail")
	public Mono<ResponseEntity<Void>> postJobFail(@PathVariable Long id, @RequestBody FailJobRequest request) {
		return scanJobRepository.findById(id).flatMap((job) -> {
			job.setStatus(JobStatus.FAILED);
			return scanJobRepository.save(job).doOnSuccess((j) -> {
				jobEventPublisher.emit(id, JobEvent.failed(id, job.getTarget(), request.reason()));
				jobEventPublisher.complete(id);
				if (job.getAssignedSlaveId() != null) {
					slaveNodeRepository.findById(job.getAssignedSlaveId())
						.flatMap((slave) -> scanJobRepository
							.countByAssignedSlaveIdAndStatus(slave.getId(), JobStatus.RUNNING)
							.flatMap((runningCount) -> {
								int maxScans = (slave.getMaxConcurrentScans() != null
										&& slave.getMaxConcurrentScans() > 0) ? slave.getMaxConcurrentScans() : 10;
								if (runningCount < maxScans) {
									return slaveNodeRepository.updateSlaveNodeStatusAndLastSeenAt(slave.getId(),
											NodeStatus.IDLE.name(), slave.getLastSeenAt());
								}
								return Mono.empty();
							}))
						.subscribe();
				}
			});
		}).map((j) -> ResponseEntity.ok().<Void>build()).defaultIfEmpty(ResponseEntity.notFound().build());
	}

	@PostMapping("/tasks/{id}/attempts")
	public Mono<ResponseEntity<Void>> postTaskAttemptsBatch(@PathVariable Long id,
			@RequestBody List<ScanAttempt> batch) {
		return scanTaskRepository.findById(id).flatMap((task) -> {
			return scanJobRepository.findById(task.getScanJobId()).flatMap((job) -> {
				int vulnsInBatch = 0;
				for (ScanAttempt attempt : batch) {
					if (attempt.vulnerabilities() != null) {
						vulnsInBatch += attempt.vulnerabilities().size();
					}
				}

				return scanResultService.saveBatch(job.getResultId(), batch)
					.then(scanJobRepository.incrementCounts(job.getId(), vulnsInBatch, batch.size()))
					.thenReturn(ResponseEntity.ok().<Void>build());
			});
		}).defaultIfEmpty(ResponseEntity.notFound().build());
	}

	public record CompleteTaskRequest(Instant startTime, Instant endTime, int testsCount, int vulnsCount) {
	}

	@PostMapping("/tasks/{id}/complete")
	public Mono<ResponseEntity<Void>> postTaskComplete(@PathVariable Long id,
			@RequestBody CompleteTaskRequest request) {
		return jobOrchestratorService.onScanTaskComplete(id, request.testsCount(), request.vulnsCount())
			.thenReturn(ResponseEntity.ok().<Void>build());
	}

	@PostMapping("/tasks/{id}/fail")
	public Mono<ResponseEntity<Void>> postTaskFail(@PathVariable Long id, @RequestBody FailJobRequest request) {
		return jobOrchestratorService.onTaskFailed(id, request.reason()).thenReturn(ResponseEntity.ok().<Void>build());
	}

	public record SlaveRegistrationRequest(String id, String url, String capabilities) {
	}

}

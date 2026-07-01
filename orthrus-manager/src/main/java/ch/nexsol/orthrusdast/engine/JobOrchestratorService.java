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

package ch.nexsol.orthrusdast.engine;

import java.time.Instant;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import ch.nexsol.orthrusdast.entity.ScanJobEntity;
import ch.nexsol.orthrusdast.entity.ScanTaskEntity;
import ch.nexsol.orthrusdast.model.JobStatus;
import ch.nexsol.orthrusdast.repository.ScanJobRepository;
import ch.nexsol.orthrusdast.repository.ScanTaskRepository;
import ch.nexsol.orthrusdast.scanner.ScannerFamily;
import ch.nexsol.orthrusdast.sse.JobEvent;

@Service
public class JobOrchestratorService {

	private static final Logger log = LoggerFactory.getLogger(JobOrchestratorService.class);

	private final ScanJobRepository scanJobRepository;

	private final ScanTaskRepository scanTaskRepository;

	private final ch.nexsol.orthrusdast.engine.ScanResultService scanResultService;

	private final ch.nexsol.orthrusdast.sse.JobEventPublisher jobEventPublisher;

	public JobOrchestratorService(ScanJobRepository scanJobRepository, ScanTaskRepository scanTaskRepository,
			ch.nexsol.orthrusdast.engine.ScanResultService scanResultService,
			ch.nexsol.orthrusdast.sse.JobEventPublisher jobEventPublisher) {
		this.scanJobRepository = scanJobRepository;
		this.scanTaskRepository = scanTaskRepository;
		this.scanResultService = scanResultService;
		this.jobEventPublisher = jobEventPublisher;
	}

	public Mono<Void> processPendingJobs() {
		return scanJobRepository.findByStatus(JobStatus.PENDING).flatMap((job) -> {
			log.info("Orchestrating new job: {}", job.getId());
			job.setStatus(JobStatus.RUNNING);
			job.setStartedAt(Instant.now());
			job.setResultId(java.util.UUID.randomUUID().toString());
			return scanResultService.createPlaceholderResult(job.getResultId(), job.getTarget(), job.getStartedAt())
				.then(scanJobRepository.save(job))
				.flatMap((savedJob) -> {
					jobEventPublisher.emit(savedJob.getId(), JobEvent.running(savedJob.getId(), savedJob.getTarget()));
					return createFamilyTasks(savedJob);
				});
		}).then();
	}

	private Mono<Void> createFamilyTasks(ScanJobEntity job) {
		return Flux.fromArray(ScannerFamily.values()).filter((f) -> f != ScannerFamily.DISCOVERY).flatMap((family) -> {
			ScanTaskEntity subTask = new ScanTaskEntity();
			subTask.setScanJobId(job.getId());
			subTask.setPhase(family.name());
			subTask.setStatus(JobStatus.PENDING);
			subTask.setCreatedAt(Instant.now());
			return scanTaskRepository.save(subTask);
		}).then();
	}

	public Mono<Void> onScanTaskComplete(Long taskId, int testsCount, int vulnsCount) {
		return scanTaskRepository.findById(taskId).flatMap((task) -> {
			log.info("Scan task {} (Family: {}) completed. {} tests executed, {} vulnerabilities found.", taskId,
					task.getPhase(), testsCount, vulnsCount);
			task.setStatus(JobStatus.COMPLETED);
			task.setCompletedAt(Instant.now());
			return scanTaskRepository.save(task).flatMap((savedTask) -> checkJobCompletion(task.getScanJobId()));
		});
	}

	public Mono<Void> onTaskFailed(Long taskId, String reason) {
		return scanTaskRepository.findById(taskId).flatMap((task) -> {
			int retryCount = task.getRetryCount() != null ? task.getRetryCount() : 0;
			if (retryCount < 3) {
				log.warn("Task {} failed (Attempt {}). Reason: {}. Retrying...", taskId, retryCount + 1, reason);
				task.setRetryCount(retryCount + 1);
				task.setStatus(JobStatus.PENDING);
				task.setAssignedSlaveId(null);
				task.setStartedAt(null);
				return scanTaskRepository.save(task).then();
			}
			else {
				log.error("Task {} permanently failed after {} attempts: {}", taskId, retryCount, reason);
				task.setStatus(JobStatus.FAILED);
				task.setCompletedAt(Instant.now());
				return scanTaskRepository.save(task).flatMap((savedTask) -> {
					return checkJobCompletion(task.getScanJobId());
				});
			}
		});
	}

	private Mono<Void> checkJobCompletion(Long jobId) {
		return scanTaskRepository.countActiveTasksForJob(jobId).flatMap((activeCount) -> {
			if (activeCount == 0) {
				log.info("All tasks completed or failed for job {}", jobId);
				return scanJobRepository.findById(jobId).flatMap((job) -> {
					return scanTaskRepository.countFailedTasksForJob(jobId).flatMap((failedCount) -> {
						if (failedCount > 0) {
							job.setStatus(JobStatus.FAILED);
						}
						else {
							job.setStatus(JobStatus.COMPLETED);
						}
						job.setCompletedAt(Instant.now());

						int testsCount = job.getTestsCount() != null ? job.getTestsCount() : 0;

						return scanResultService
							.finalizeJobResult(job.getResultId(), job.getTarget(), job.getStartedAt(),
									job.getCompletedAt(), testsCount)
							.flatMap((result) -> scanJobRepository.save(job).doOnSuccess((j) -> {
								if (j.getStatus() == JobStatus.FAILED) {
									jobEventPublisher.emit(jobId,
											JobEvent.failed(jobId, job.getTarget(), "Some tasks failed"));
								}
								else {
									long critical = result.riskSummary()
										.getOrDefault(ch.nexsol.orthrusdast.model.RiskLevel.CRITICAL, 0L);
									long high = result.riskSummary()
										.getOrDefault(ch.nexsol.orthrusdast.model.RiskLevel.HIGH, 0L);
									long medium = result.riskSummary()
										.getOrDefault(ch.nexsol.orthrusdast.model.RiskLevel.MEDIUM, 0L);
									long low = result.riskSummary()
										.getOrDefault(ch.nexsol.orthrusdast.model.RiskLevel.LOW, 0L);
									String grade = "A";
									if (critical > 0)
										grade = "F";
									else if (high > 0)
										grade = "D";
									else if (medium > 0)
										grade = "C";
									else if (low > 0)
										grade = "B";

									long info = result.riskSummary()
										.getOrDefault(ch.nexsol.orthrusdast.model.RiskLevel.INFO, 0L);

									jobEventPublisher.emit(jobId,
											JobEvent.completed(jobId, job.getTarget(), result.id(), grade,
													result.vulnerabilities().size(), critical, high, medium, low, info,
													result.operationsScanned()));
								}
								jobEventPublisher.complete(jobId);
							}))
							.then();
					});
				});
			}
			return Mono.empty();
		});
	}

}

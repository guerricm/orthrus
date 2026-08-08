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

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import ch.nexsol.orthrusdast.entity.ScanJobEntity;
import ch.nexsol.orthrusdast.entity.ScanTaskEntity;
import ch.nexsol.orthrusdast.model.JobStatus;
import ch.nexsol.orthrusdast.repository.ScanJobRepository;
import ch.nexsol.orthrusdast.repository.ScanTaskRepository;
import ch.nexsol.orthrusdast.repository.SlaveNodeRepository;
import ch.nexsol.orthrusdast.scanner.ScannerFamily;
import ch.nexsol.orthrusdast.sse.JobEvent;
import ch.nexsol.orthrusdast.sse.JobEventPublisher;

/**
 * Owns the lifecycle of a scan job: splitting it into per-family tasks, reacting to task
 * outcomes, and closing the job once no task is left running.
 */
@Service
public class JobOrchestratorService {

	private static final Logger log = LoggerFactory.getLogger(JobOrchestratorService.class);

	/**
	 * How many times a task is requeued before the job is failed.
	 */
	static final int MAX_TASK_ATTEMPTS = 3;

	private final ScanJobRepository scanJobRepository;

	private final ScanTaskRepository scanTaskRepository;

	private final ScanResultService scanResultService;

	private final JobEventPublisher jobEventPublisher;

	private final SlaveNodeRepository slaveNodeRepository;

	private final WebClient webClient;

	public JobOrchestratorService(ScanJobRepository scanJobRepository, ScanTaskRepository scanTaskRepository,
			ScanResultService scanResultService, JobEventPublisher jobEventPublisher,
			SlaveNodeRepository slaveNodeRepository, WebClient.Builder webClientBuilder) {
		this.scanJobRepository = scanJobRepository;
		this.scanTaskRepository = scanTaskRepository;
		this.scanResultService = scanResultService;
		this.jobEventPublisher = jobEventPublisher;
		this.slaveNodeRepository = slaveNodeRepository;
		this.webClient = webClientBuilder.build();
	}

	public Mono<Void> processPendingJobs() {
		return this.scanJobRepository.findByStatus(JobStatus.PENDING).concatMap(this::startJob).then();
	}

	/**
	 * Moves one queued job into execution: claim it, give it a result row to write into,
	 * then split it into per-family tasks.
	 * @param job the queued job
	 * @return completion signal
	 */
	private Mono<Void> startJob(ScanJobEntity job) {
		Instant startedAt = Instant.now();
		String resultId = UUID.randomUUID().toString();

		return this.scanJobRepository.claimForOrchestration(job.getId(), startedAt)
			.defaultIfEmpty(0)
			.flatMap((claimed) -> {
				if (claimed != 1) {
					log.debug("Job {} was already picked up by another dispatch cycle.", job.getId());
					return Mono.empty();
				}

				log.info("Orchestrating new job: {}", job.getId());
				job.setStatus(JobStatus.RUNNING);
				job.setStartedAt(startedAt);
				job.setResultId(resultId);

				// scan_jobs.result_id is a foreign key onto scan_results.
				return this.scanResultService.createPlaceholderResult(resultId, job.getTarget(), startedAt)
					.then(this.scanJobRepository.attachResult(job.getId(), resultId))
					.then(Mono.defer(() -> {
						this.jobEventPublisher.emit(job.getId(), JobEvent.running(job.getId(), job.getTarget()));
						return createFamilyTasks(job);
					}));
			})
			.then();
	}

	private Mono<Void> createFamilyTasks(ScanJobEntity job) {
		return Flux.fromArray(ScannerFamily.values()).filter((f) -> f != ScannerFamily.DISCOVERY).flatMap((family) -> {
			ScanTaskEntity subTask = new ScanTaskEntity();
			subTask.setScanJobId(job.getId());
			subTask.setPhase(family.name());
			subTask.setStatus(JobStatus.PENDING);
			subTask.setCreatedAt(Instant.now());
			return this.scanTaskRepository.save(subTask);
		}).then();
	}

	public Mono<Void> onScanTaskComplete(Long taskId, int testsCount, int vulnsCount) {
		return this.scanTaskRepository.findById(taskId).flatMap((task) -> {
			log.info("Scan task {} (Family: {}) completed. {} tests executed, {} vulnerabilities found.", taskId,
					task.getPhase(), testsCount, vulnsCount);
			task.setStatus(JobStatus.COMPLETED);
			task.setCompletedAt(Instant.now());
			return this.scanTaskRepository.save(task)
				.flatMap((savedTask) -> checkJobCompletion(savedTask.getScanJobId()));
		});
	}

	public Mono<Void> onTaskFailed(Long taskId, String reason) {
		return this.scanTaskRepository.findById(taskId).flatMap((task) -> {
			int attempts = (task.getRetryCount() != null) ? task.getRetryCount() : 0;
			if (attempts < MAX_TASK_ATTEMPTS) {
				log.warn("Task {} failed (Attempt {}). Reason: {}. Retrying...", taskId, attempts + 1, reason);
				return requeue(task).then();
			}
			log.error("Task {} permanently failed after {} attempts: {}", taskId, attempts, reason);
			task.setStatus(JobStatus.FAILED);
			task.setCompletedAt(Instant.now());
			return this.scanTaskRepository.save(task)
				.flatMap((savedTask) -> checkJobCompletion(savedTask.getScanJobId()));
		});
	}

	/**
	 * Requeues every task a worker was still holding, for when it re-registers after a
	 * restart or is detected offline.
	 * @param slaveId the worker that dropped its work
	 * @param reason why the tasks are being recovered
	 * @return completion signal
	 */
	public Mono<Void> recoverTasksOfSlave(String slaveId, String reason) {
		return this.scanTaskRepository.findByAssignedSlaveIdAndStatus(slaveId, JobStatus.RUNNING).flatMap((task) -> {
			int attempts = (task.getRetryCount() != null) ? task.getRetryCount() : 0;
			if (attempts < MAX_TASK_ATTEMPTS) {
				log.info("Requeueing task {} (Attempt {}) because slave {} dropped it: {}", task.getId(), attempts + 1,
						slaveId, reason);
				return requeue(task).then();
			}
			log.warn("Failing task {} after {} attempts, slave {} dropped it: {}", task.getId(), attempts, slaveId,
					reason);
			task.setStatus(JobStatus.FAILED);
			task.setCompletedAt(Instant.now());
			return this.scanTaskRepository.save(task)
				.flatMap((savedTask) -> checkJobCompletion(savedTask.getScanJobId()));
		}).then();
	}

	private Mono<ScanTaskEntity> requeue(ScanTaskEntity task) {
		int attempts = (task.getRetryCount() != null) ? task.getRetryCount() : 0;
		task.setRetryCount(attempts + 1);
		task.setStatus(JobStatus.PENDING);
		task.setAssignedSlaveId(null);
		task.setStartedAt(null);
		return this.scanTaskRepository.save(task);
	}

	/**
	 * Cancels a job: its queued and running tasks are marked cancelled, and every worker
	 * holding one of them is told to drop it.
	 * @param jobId the job to cancel
	 * @return completion signal
	 */
	public Mono<Void> cancelJob(Long jobId) {
		return this.scanJobRepository.findById(jobId)
			.flatMap((job) -> this.scanJobRepository.cancelJob(jobId, Instant.now())
				.defaultIfEmpty(0)
				.filter((cancelled) -> cancelled == 1)
				.flatMap((cancelled) -> {
					job.setStatus(JobStatus.CANCELLED);
					return this.scanTaskRepository.findByScanJobId(jobId)
						.filter((task) -> task.getStatus() == JobStatus.PENDING
								|| task.getStatus() == JobStatus.RUNNING)
						.concatMap(this::cancelTask)
						.then(Mono.fromRunnable(() -> {
							this.jobEventPublisher.emit(jobId,
									JobEvent.failed(jobId, job.getTarget(), "Scan cancelled by user"));
							this.jobEventPublisher.complete(jobId);
						}));
				}))
			.then();
	}

	private Mono<Void> cancelTask(ScanTaskEntity task) {
		String slaveId = task.getAssignedSlaveId();
		task.setStatus(JobStatus.CANCELLED);
		task.setCompletedAt(Instant.now());

		Mono<Void> notifySlave = (slaveId != null) ? this.slaveNodeRepository.findById(slaveId)
			.flatMap((slave) -> this.webClient.delete()
				.uri(slave.getUrl() + "/api/v1/slave/tasks/" + task.getId())
				.retrieve()
				.bodyToMono(Void.class)
				.timeout(Duration.ofSeconds(5))
				.onErrorResume((e) -> {
					log.warn("Could not cancel task {} on slave {}: {}", task.getId(), slaveId, e.getMessage());
					return Mono.empty();
				}))
			.then() : Mono.empty();

		return this.scanTaskRepository.save(task).then(notifySlave);
	}

	/**
	 * Completes a task no node in the fleet can run, so its job is not held open by a
	 * capability the fleet lacks.
	 * @param taskId the unplaceable task
	 * @param reason why no node can run it
	 * @return completion signal
	 */
	public Mono<Void> onTaskUnsupported(Long taskId, String reason) {
		return this.scanTaskRepository.findById(taskId)
			.flatMap((task) -> this.scanTaskRepository.completeUnsupported(taskId, Instant.now())
				.defaultIfEmpty(0)
				.flatMap((closed) -> {
					if (closed != 1) {
						log.debug("Task {} was already closed by another cycle.", taskId);
						return Mono.empty();
					}
					log.info("Task {} ({}) completed without running: {}", taskId, task.getPhase(), reason);
					return checkJobCompletion(task.getScanJobId());
				}));
	}

	private Mono<Void> checkJobCompletion(Long jobId) {
		return this.scanTaskRepository.countActiveTasksForJob(jobId).flatMap((activeCount) -> {
			if (activeCount > 0) {
				return Mono.empty();
			}
			return this.scanJobRepository.findById(jobId)
				.filter((job) -> job.getStatus() == JobStatus.RUNNING)
				.flatMap((job) -> this.scanTaskRepository.countFailedTasksForJob(jobId)
					.flatMap((failedCount) -> closeJob(job, failedCount > 0)));
		});
	}

	/**
	 * Writes the job's terminal status and announces the outcome. The status update is
	 * conditional and only the caller that wins it publishes, so a job whose last tasks
	 * finish at the same moment is still reported once.
	 * @param job the job whose tasks have all finished
	 * @param failed whether any of its tasks failed
	 * @return completion signal
	 */
	private Mono<Void> closeJob(ScanJobEntity job, boolean failed) {
		Instant completedAt = Instant.now();
		JobStatus status = failed ? JobStatus.FAILED : JobStatus.COMPLETED;
		int testsCount = (job.getTestsCount() != null) ? job.getTestsCount() : 0;

		return this.scanJobRepository.finishJob(job.getId(), status.name(), completedAt)
			.defaultIfEmpty(0)
			.flatMap((finished) -> {
				if (finished != 1) {
					log.debug("Job {} was already finalised by another cycle.", job.getId());
					return Mono.empty();
				}

				log.info("All tasks completed or failed for job {}", job.getId());
				job.setStatus(status);
				job.setCompletedAt(completedAt);

				return this.scanResultService
					.finalizeJobResult(job.getResultId(), job.getTarget(), job.getStartedAt(), completedAt, testsCount)
					.doOnNext((result) -> {
						if (status == JobStatus.FAILED) {
							this.jobEventPublisher.emit(job.getId(),
									JobEvent.failed(job.getId(), job.getTarget(), "Some tasks failed"));
						}
						else {
							this.jobEventPublisher.emit(job.getId(),
									JobEvent.completed(job.getId(), job.getTarget(), result));
						}
						this.jobEventPublisher.complete(job.getId());
					})
					.then();
			});
	}

}

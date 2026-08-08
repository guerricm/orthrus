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

import org.springframework.dao.DuplicateKeyException;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import ch.nexsol.orthrusdast.engine.JobOrchestratorService;
import ch.nexsol.orthrusdast.engine.ScanResultService;
import ch.nexsol.orthrusdast.entity.SlaveNodeEntity;
import ch.nexsol.orthrusdast.model.NodeStatus;
import ch.nexsol.orthrusdast.model.ScanAttempt;
import ch.nexsol.orthrusdast.repository.ScanJobRepository;
import ch.nexsol.orthrusdast.repository.ScanTaskRepository;
import ch.nexsol.orthrusdast.repository.SlaveNodeRepository;

/**
 * Endpoints called by worker nodes, protected by a shared secret rather than by the
 * session-cookie chain used for the UI.
 */
@RestController
@RequestMapping("/api/internal")
public class MasterInternalApiController {

	private static final int DEFAULT_MAX_CONCURRENT_SCANS = 10;

	private final SlaveNodeRepository slaveNodeRepository;

	private final ScanJobRepository scanJobRepository;

	private final ScanResultService scanResultService;

	private final JobOrchestratorService jobOrchestratorService;

	private final ScanTaskRepository scanTaskRepository;

	public MasterInternalApiController(SlaveNodeRepository slaveNodeRepository, ScanJobRepository scanJobRepository,
			ScanResultService scanResultService, JobOrchestratorService jobOrchestratorService,
			ScanTaskRepository scanTaskRepository) {
		this.slaveNodeRepository = slaveNodeRepository;
		this.scanJobRepository = scanJobRepository;
		this.scanResultService = scanResultService;
		this.jobOrchestratorService = jobOrchestratorService;
		this.scanTaskRepository = scanTaskRepository;
	}

	/**
	 * Registers a worker. A worker that re-registers has restarted, so any task it was
	 * still holding is requeued.
	 * @param request the registration request
	 * @return a mono containing the registered slave node
	 */
	@PostMapping("/slaves/register")
	public Mono<ResponseEntity<SlaveNodeEntity>> registerSlave(@RequestBody SlaveRegistrationRequest request) {
		SlaveNodeEntity node = new SlaveNodeEntity(request.id(), request.url(), NodeStatus.IDLE,
				request.capabilities());
		return upsertNode(node)
			.then(this.jobOrchestratorService.recoverTasksOfSlave(node.getId(), "Slave node restarted"))
			.thenReturn(ResponseEntity.ok(node));
	}

	/**
	 * Records the node, whether or not it is already known.
	 * <p>
	 * A worker registers on startup and re-registers whenever a heartbeat is rejected, so
	 * two registrations can be in flight at once. Testing for the row first would let
	 * both conclude it is absent and insert, so the insert is treated as the optimistic
	 * path and a lost race falls back to an update.
	 * @param node the node announcing itself
	 * @return completion signal
	 */
	private Mono<Void> upsertNode(SlaveNodeEntity node) {
		return touchNode(node).flatMap((rows) -> (rows > 0) ? Mono.<Void>empty()
				: this.slaveNodeRepository
					.insertSlaveNode(node.getId(), node.getUrl(), node.getStatus(), node.getCapabilities(),
							node.getLastSeenAt())
					.onErrorResume(DuplicateKeyException.class, (e) -> touchNode(node).then()))
			.then();
	}

	private Mono<Integer> touchNode(SlaveNodeEntity node) {
		return this.slaveNodeRepository.updateSlaveNodeUrlStatusCapabilitiesAndLastSeenAt(node.getId(), node.getUrl(),
				node.getStatus().name(), node.getCapabilities(), node.getLastSeenAt());
	}

	/**
	 * Reports a worker's liveness and current load. The worker owns the load figure; the
	 * master alone turns it into a {@link NodeStatus}.
	 * @param id the slave ID
	 * @param activeTasks the number of tasks currently running on that node
	 * @param url the url the node wants to be reached on
	 * @return a mono of response entity
	 */
	@PostMapping("/slaves/{id}/heartbeat")
	public Mono<ResponseEntity<Void>> slaveHeartbeat(@PathVariable String id,
			@RequestParam(defaultValue = "0") int activeTasks, @RequestParam(required = false) String url) {

		return this.slaveNodeRepository.findById(id).flatMap((slave) -> {
			int maxScans = (slave.getMaxConcurrentScans() != null && slave.getMaxConcurrentScans() > 0)
					? slave.getMaxConcurrentScans() : DEFAULT_MAX_CONCURRENT_SCANS;
			NodeStatus status = (activeTasks >= maxScans) ? NodeStatus.BUSY : NodeStatus.IDLE;

			if (url != null && !url.trim().isEmpty()) {
				return this.slaveNodeRepository.updateSlaveNodeUrlStatusAndLastSeenAt(id, url, status.name(),
						Instant.now());
			}
			return this.slaveNodeRepository.updateSlaveNodeStatusAndLastSeenAt(id, status.name(), Instant.now());
		})
			.map((rows) -> (rows == 0) ? ResponseEntity.notFound().<Void>build() : ResponseEntity.ok().<Void>build())
			.defaultIfEmpty(ResponseEntity.notFound().build());
	}

	/**
	 * Marks a worker offline as it shuts down gracefully.
	 * @param id the slave ID
	 * @return a mono of response entity
	 */
	@PostMapping("/slaves/{id}/offline")
	public Mono<ResponseEntity<Void>> slaveOffline(@PathVariable String id) {
		return this.slaveNodeRepository.updateSlaveNodeStatusAndLastSeenAt(id, NodeStatus.OFFLINE.name(), Instant.now())
			.map((rows) -> (rows == 0) ? ResponseEntity.notFound().<Void>build() : ResponseEntity.ok().<Void>build())
			.defaultIfEmpty(ResponseEntity.notFound().build());
	}

	/**
	 * Records a batch of attempts produced by one of a job's tasks.
	 * @param id the task ID
	 * @param batch the batch of attempts
	 * @return a mono of response entity
	 */
	@PostMapping("/tasks/{id}/attempts")
	public Mono<ResponseEntity<Void>> postTaskAttemptsBatch(@PathVariable Long id,
			@RequestBody List<ScanAttempt> batch) {
		return this.scanTaskRepository.findById(id)
			.flatMap((task) -> this.scanJobRepository.findById(task.getScanJobId()).flatMap((job) -> {
				int vulnsInBatch = 0;
				for (ScanAttempt attempt : batch) {
					if (attempt.vulnerabilities() != null) {
						vulnsInBatch += attempt.vulnerabilities().size();
					}
				}

				return this.scanResultService.saveBatch(job.getResultId(), batch)
					.then(this.scanJobRepository.incrementCounts(job.getId(), vulnsInBatch, batch.size()))
					.thenReturn(ResponseEntity.ok().<Void>build());
			}))
			.defaultIfEmpty(ResponseEntity.notFound().build());
	}

	@PostMapping("/tasks/{id}/complete")
	public Mono<ResponseEntity<Void>> postTaskComplete(@PathVariable Long id,
			@RequestBody CompleteTaskRequest request) {
		return this.jobOrchestratorService.onScanTaskComplete(id, request.testsCount(), request.vulnsCount())
			.thenReturn(ResponseEntity.ok().<Void>build());
	}

	@PostMapping("/tasks/{id}/fail")
	public Mono<ResponseEntity<Void>> postTaskFail(@PathVariable Long id, @RequestBody FailTaskRequest request) {
		return this.jobOrchestratorService.onTaskFailed(id, request.reason())
			.thenReturn(ResponseEntity.ok().<Void>build());
	}

	public record SlaveRegistrationRequest(String id, String url, String capabilities) {
	}

	record FailTaskRequest(String reason) {
	}

	public record CompleteTaskRequest(Instant startTime, Instant endTime, int testsCount, int vulnsCount) {
	}

}

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

package ch.nexsol.orthrusdast.repository;

import java.time.Instant;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import ch.nexsol.orthrusdast.entity.ScanTaskEntity;
import ch.nexsol.orthrusdast.model.JobStatus;

@Repository
public interface ScanTaskRepository extends R2dbcRepository<ScanTaskEntity, Long> {

	Mono<Long> countByStatus(JobStatus status);

	Flux<ScanTaskEntity> findByStatus(JobStatus status);

	Flux<ScanTaskEntity> findByScanJobId(Long scanJobId);

	Mono<Long> countByAssignedSlaveIdAndStatus(String assignedSlaveId, JobStatus status);

	@Query("SELECT COUNT(id) FROM scan_tasks WHERE scan_job_id = :scanJobId AND status NOT IN ('COMPLETED', 'FAILED', 'CANCELLED')")
	Mono<Long> countActiveTasksForJob(Long scanJobId);

	@Query("SELECT COUNT(id) FROM scan_tasks WHERE scan_job_id = :scanJobId AND status = 'FAILED'")
	Mono<Long> countFailedTasksForJob(Long scanJobId);

	Flux<ScanTaskEntity> findByAssignedSlaveIdAndStatus(String assignedSlaveId, JobStatus status);

	/**
	 * Takes ownership of a pending task for the node about to receive it. The status
	 * guard makes dispatch exactly-once across concurrent cycles and manager instances
	 * alike.
	 * @param id the task to claim
	 * @param slaveId the node the task is being handed to
	 * @param startedAt when the claim was made
	 * @return 1 when this caller won the task, 0 when someone else already had it
	 */
	@Modifying
	@Query("UPDATE scan_tasks SET status = 'RUNNING', assigned_slave_id = :slaveId, started_at = :startedAt "
			+ "WHERE id = :id AND status = 'PENDING'")
	Mono<Integer> claimForDispatch(Long id, String slaveId, Instant startedAt);

	/**
	 * Completes a task no node can run, guarded so only one caller closes it.
	 * @param id the task
	 * @param completedAt when it was closed
	 * @return 1 when this caller closed the task, 0 when someone else already had
	 */
	@Modifying
	@Query("UPDATE scan_tasks SET status = 'COMPLETED', completed_at = :completedAt "
			+ "WHERE id = :id AND status = 'PENDING'")
	Mono<Integer> completeUnsupported(Long id, Instant completedAt);

}

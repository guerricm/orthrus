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

	@Query("SELECT COUNT(id) FROM scan_tasks WHERE scan_job_id = :scanJobId AND status != 'COMPLETED' AND status != 'FAILED'")
	Mono<Long> countActiveTasksForJob(Long scanJobId);

	@Query("SELECT COUNT(id) FROM scan_tasks WHERE scan_job_id = :scanJobId AND status = 'FAILED'")
	Mono<Long> countFailedTasksForJob(Long scanJobId);

	Flux<ScanTaskEntity> findByAssignedSlaveIdAndStatus(String assignedSlaveId, JobStatus status);

}

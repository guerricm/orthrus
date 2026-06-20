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
import java.util.List;

import org.springframework.data.domain.Pageable;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import ch.nexsol.orthrusdast.entity.ScanJobEntity;
import ch.nexsol.orthrusdast.model.JobStatus;

@Repository
public interface ScanJobRepository extends R2dbcRepository<ScanJobEntity, Long> {

	Flux<ScanJobEntity> findByStatus(JobStatus status);

	Flux<ScanJobEntity> findByStatusIn(List<JobStatus> statuses);

	Flux<ScanJobEntity> findByAssignedSlaveIdAndStatus(String assignedSlaveId, JobStatus status);

	Flux<ScanJobEntity> findByStatusAndStartedAtBefore(JobStatus status, Instant startedAtBefore);

	Flux<ScanJobEntity> findAllByOrderByCreatedAtDesc(Pageable pageable);

	Mono<Long> countByAssignedSlaveIdAndStatus(String assignedSlaveId, JobStatus status);

	Mono<ScanJobEntity> findByResultId(String resultId);

	@org.springframework.data.r2dbc.repository.Modifying
	@org.springframework.data.r2dbc.repository.Query("UPDATE scan_jobs SET vulns_count = COALESCE(vulns_count, 0) + :vulns, tests_count = COALESCE(tests_count, 0) + :tests WHERE id = :id")
	Mono<Integer> incrementCounts(Long id, int vulns, int tests);

}

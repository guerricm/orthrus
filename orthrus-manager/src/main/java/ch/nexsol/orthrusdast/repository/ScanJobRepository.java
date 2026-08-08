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

	Mono<Long> countByStatus(JobStatus status);

	Flux<ScanJobEntity> findByStatus(JobStatus status);

	Flux<ScanJobEntity> findByStatusIn(List<JobStatus> statuses);

	Flux<ScanJobEntity> findByStatusAndStartedAtBefore(JobStatus status, Instant startedAtBefore);

	Flux<ScanJobEntity> findAllByOrderByCreatedAtDesc(Pageable pageable);

	Mono<ScanJobEntity> findByResultId(String resultId);

	@org.springframework.data.r2dbc.repository.Modifying
	@org.springframework.data.r2dbc.repository.Query("UPDATE scan_jobs SET vulns_count = COALESCE(vulns_count, 0) + :vulns, tests_count = COALESCE(tests_count, 0) + :tests WHERE id = :id")
	Mono<Integer> incrementCounts(Long id, int vulns, int tests);

	/**
	 * Records which node is running the job, touching that column only: a whole-row write
	 * would race with {@link #incrementCounts}.
	 * @param id the job
	 * @param slaveId the node the job's tasks are pinned to
	 * @return the number of rows updated
	 */
	@org.springframework.data.r2dbc.repository.Modifying
	@org.springframework.data.r2dbc.repository.Query("UPDATE scan_jobs SET assigned_slave_id = :slaveId WHERE id = :id")
	Mono<Integer> assignSlave(Long id, String slaveId);

	/**
	 * Takes ownership of a queued job before splitting it into tasks. The status guard
	 * stops concurrent cycles from each building a set of family tasks for it.
	 * @param id the job to claim
	 * @param startedAt when the claim was made
	 * @return 1 when this caller won the job, 0 when someone else already had it
	 */
	@org.springframework.data.r2dbc.repository.Modifying
	@org.springframework.data.r2dbc.repository.Query("UPDATE scan_jobs SET status = 'RUNNING', started_at = :startedAt WHERE id = :id AND status = 'PENDING'")
	Mono<Integer> claimForOrchestration(Long id, Instant startedAt);

	/**
	 * Links the job to its result row, once that row exists.
	 * @param id the job
	 * @param resultId the result row it writes into
	 * @return the number of rows updated
	 */
	@org.springframework.data.r2dbc.repository.Modifying
	@org.springframework.data.r2dbc.repository.Query("UPDATE scan_jobs SET result_id = :resultId WHERE id = :id")
	Mono<Integer> attachResult(Long id, String resultId);

	/**
	 * Moves a running job to its terminal status. Only the caller that gets 1 back should
	 * publish the outcome, so the job is finalised and announced exactly once.
	 * @param id the job
	 * @param status the terminal status
	 * @param completedAt when the job ended
	 * @return 1 when this caller closed the job, 0 when it was no longer running
	 */
	@org.springframework.data.r2dbc.repository.Modifying
	@org.springframework.data.r2dbc.repository.Query("UPDATE scan_jobs SET status = :status, completed_at = :completedAt WHERE id = :id AND status = 'RUNNING'")
	Mono<Integer> finishJob(Long id, String status, Instant completedAt);

	/**
	 * Cancels a job that has not finished yet. Only the caller that gets 1 back should
	 * stop its tasks and publish the outcome.
	 * @param id the job
	 * @param completedAt when the job was cancelled
	 * @return 1 when this caller cancelled the job, 0 when it had already finished
	 */
	@org.springframework.data.r2dbc.repository.Modifying
	@org.springframework.data.r2dbc.repository.Query("UPDATE scan_jobs SET status = 'CANCELLED', completed_at = :completedAt WHERE id = :id AND status IN ('PENDING', 'RUNNING')")
	Mono<Integer> cancelJob(Long id, Instant completedAt);

}

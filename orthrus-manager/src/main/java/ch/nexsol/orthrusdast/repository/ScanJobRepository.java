package ch.nexsol.orthrusdast.repository;

import ch.nexsol.orthrusdast.entity.ScanJobEntity;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;

import ch.nexsol.orthrusdast.model.JobStatus;

import java.time.Instant;
import java.util.List;
import org.springframework.data.domain.Pageable;
import reactor.core.publisher.Mono;

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

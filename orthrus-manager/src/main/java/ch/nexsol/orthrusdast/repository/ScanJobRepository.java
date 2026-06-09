package ch.nexsol.orthrusdast.repository;

import ch.nexsol.orthrusdast.entity.ScanJobEntity;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;

import ch.nexsol.orthrusdast.model.JobStatus;

@Repository
public interface ScanJobRepository extends R2dbcRepository<ScanJobEntity, Long> {

	Flux<ScanJobEntity> findByStatus(JobStatus status);

	Flux<ScanJobEntity> findByStatusIn(java.util.List<JobStatus> statuses);

	Flux<ScanJobEntity> findByAssignedSlaveIdAndStatus(String assignedSlaveId, JobStatus status);

	Flux<ScanJobEntity> findByStatusAndStartedAtBefore(JobStatus status, java.time.Instant startedAtBefore);

	Flux<ScanJobEntity> findAllByOrderByCreatedAtDesc(org.springframework.data.domain.Pageable pageable);

	reactor.core.publisher.Mono<Long> countByAssignedSlaveIdAndStatus(String assignedSlaveId, JobStatus status);

	reactor.core.publisher.Mono<ScanJobEntity> findByResultId(String resultId);

}

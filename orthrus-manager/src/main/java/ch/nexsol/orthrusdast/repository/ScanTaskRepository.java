package ch.nexsol.orthrusdast.repository;

import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import org.springframework.stereotype.Repository;

import ch.nexsol.orthrusdast.entity.ScanTaskEntity;
import ch.nexsol.orthrusdast.model.JobStatus;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Repository
public interface ScanTaskRepository extends ReactiveCrudRepository<ScanTaskEntity, Long> {

	Flux<ScanTaskEntity> findByStatus(JobStatus status);

	Flux<ScanTaskEntity> findByScanJobId(Long scanJobId);

	Mono<Long> countByAssignedSlaveIdAndStatus(String assignedSlaveId, JobStatus status);

	@Query("SELECT COUNT(id) FROM scan_tasks WHERE scan_job_id = :scanJobId AND status != 'COMPLETED' AND status != 'FAILED'")
	Mono<Long> countActiveTasksForJob(Long scanJobId);

	Flux<ScanTaskEntity> findByAssignedSlaveIdAndStatus(String assignedSlaveId, JobStatus status);

}

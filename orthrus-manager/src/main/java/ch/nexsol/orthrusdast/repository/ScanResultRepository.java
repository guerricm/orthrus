package ch.nexsol.orthrusdast.repository;

import ch.nexsol.orthrusdast.entity.ScanResultEntity;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import org.springframework.data.domain.Pageable;
import reactor.core.publisher.Flux;

import java.time.Instant;
import org.springframework.data.r2dbc.repository.Query;
import reactor.core.publisher.Mono;

public interface ScanResultRepository extends ReactiveCrudRepository<ScanResultEntity, String> {

	Flux<ScanResultEntity> findAllByOrderByScanStartTimeDesc(Pageable pageable);

	@Query("UPDATE scan_results SET scan_end_time = :endTime, operations_scanned = :testsCount WHERE id = :id")
	Mono<Integer> finalizeScanResult(String id, Instant endTime, int testsCount);

}

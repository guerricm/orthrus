package ch.nexsol.orthrusdast.repository;

import ch.nexsol.orthrusdast.entity.ScanResultEntity;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import org.springframework.data.domain.Pageable;
import reactor.core.publisher.Flux;

public interface ScanResultRepository extends ReactiveCrudRepository<ScanResultEntity, String> {
    Flux<ScanResultEntity> findAllByOrderByScanStartTimeDesc(Pageable pageable);

    @org.springframework.data.r2dbc.repository.Query("UPDATE scan_results SET scan_end_time = :endTime, operations_scanned = :testsCount WHERE id = :id")
    reactor.core.publisher.Mono<Integer> finalizeScanResult(String id, java.time.Instant endTime, int testsCount);
}

package ch.hug.orthrusdast.repository;

import ch.hug.orthrusdast.entity.ScanResultEntity;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import org.springframework.data.domain.Pageable;
import reactor.core.publisher.Flux;

public interface ScanResultRepository extends ReactiveCrudRepository<ScanResultEntity, String> {
    Flux<ScanResultEntity> findAllByOrderByScanStartTimeDesc(Pageable pageable);
}

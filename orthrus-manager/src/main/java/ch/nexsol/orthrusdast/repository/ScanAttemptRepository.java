package ch.nexsol.orthrusdast.repository;

import ch.nexsol.orthrusdast.entity.ScanAttemptEntity;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;

@Repository
public interface ScanAttemptRepository extends ReactiveCrudRepository<ScanAttemptEntity, Long> {

	Flux<ScanAttemptEntity> findByScanResultId(String scanResultId);

}

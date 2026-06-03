package ch.hug.orthrusdast.repository;

import ch.hug.orthrusdast.entity.SlaveNodeEntity;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;

import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.r2dbc.repository.Modifying;
import reactor.core.publisher.Mono;

import ch.hug.orthrusdast.model.NodeStatus;

@Repository
public interface SlaveNodeRepository extends R2dbcRepository<SlaveNodeEntity, String> {

    Flux<SlaveNodeEntity> findByStatus(NodeStatus status);
    
    @Modifying
    @Query("INSERT INTO \"slave_nodes\" (id, url, status, last_seen_at) VALUES (:id, :url, :status, :lastSeenAt)")
    Mono<Void> insertSlaveNode(String id, String url, NodeStatus status, java.time.Instant lastSeenAt);
    
    @Modifying
    @Query("UPDATE \"slave_nodes\" SET status = :status, last_seen_at = :lastSeenAt WHERE id = :id")
    Mono<Integer> updateSlaveNodeStatusAndLastSeenAt(String id, String status, java.time.Instant lastSeenAt);

    @Modifying
    @Query("UPDATE \"slave_nodes\" SET url = :url, status = :status, last_seen_at = :lastSeenAt WHERE id = :id")
    Mono<Integer> updateSlaveNodeUrlStatusAndLastSeenAt(String id, String url, String status, java.time.Instant lastSeenAt);

    @Modifying
    @Query("UPDATE \"slave_nodes\" SET max_concurrent_scans = :maxConcurrentScans WHERE id = :id")
    Mono<Integer> updateSlaveNodeMaxConcurrentScans(String id, int maxConcurrentScans);

    @Modifying
    @Query("UPDATE \"slave_nodes\" SET is_active = :isActive WHERE id = :id")
    Mono<Integer> updateSlaveNodeIsActive(String id, boolean isActive);

    @Modifying
    @Query("UPDATE \"slave_nodes\" SET status = 'OFFLINE' WHERE status != 'OFFLINE' AND last_seen_at < :cutoff")
    Mono<Integer> markOfflineSlaves(java.time.Instant cutoff);
}

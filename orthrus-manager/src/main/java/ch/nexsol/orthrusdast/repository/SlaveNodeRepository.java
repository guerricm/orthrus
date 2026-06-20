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

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import ch.nexsol.orthrusdast.entity.SlaveNodeEntity;
import ch.nexsol.orthrusdast.model.NodeStatus;

@Repository
public interface SlaveNodeRepository extends R2dbcRepository<SlaveNodeEntity, String> {

	Flux<SlaveNodeEntity> findByStatus(NodeStatus status);

	@Modifying
	@Query("INSERT INTO \"slave_nodes\" (id, url, status, last_seen_at) VALUES (:id, :url, :status, :lastSeenAt)")
	Mono<Void> insertSlaveNode(String id, String url, NodeStatus status, Instant lastSeenAt);

	@Modifying
	@Query("UPDATE \"slave_nodes\" SET status = :status, last_seen_at = :lastSeenAt WHERE id = :id")
	Mono<Integer> updateSlaveNodeStatusAndLastSeenAt(String id, String status, Instant lastSeenAt);

	@Modifying
	@Query("UPDATE \"slave_nodes\" SET url = :url, status = :status, last_seen_at = :lastSeenAt WHERE id = :id")
	Mono<Integer> updateSlaveNodeUrlStatusAndLastSeenAt(String id, String url, String status, Instant lastSeenAt);

	@Modifying
	@Query("UPDATE \"slave_nodes\" SET max_concurrent_scans = :maxConcurrentScans WHERE id = :id")
	Mono<Integer> updateSlaveNodeMaxConcurrentScans(String id, int maxConcurrentScans);

	@Modifying
	@Query("UPDATE \"slave_nodes\" SET is_active = :isActive WHERE id = :id")
	Mono<Integer> updateSlaveNodeIsActive(String id, boolean isActive);

	@Modifying
	@Query("UPDATE \"slave_nodes\" SET status = 'OFFLINE' WHERE status != 'OFFLINE' AND last_seen_at < :cutoff")
	Mono<Integer> markOfflineSlaves(Instant cutoff);

}

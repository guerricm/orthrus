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

package ch.nexsol.orthrusdast.client;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import ch.nexsol.orthrus.protocol.node.NodeClient;
import ch.nexsol.orthrus.protocol.node.ScanAttempt;
import ch.nexsol.orthrusdast.config.OrthrusProperties;
import ch.nexsol.orthrusdast.engine.ScanService;

/**
 * This worker's side of the master's internal API. The protocol itself lives in the
 * shared {@link NodeClient}; this component adds what is specific to a deterministic
 * worker: the discoverers, scanners and families it advertises, and when it registers and
 * heartbeats.
 */
@Component
@EnableScheduling
@ConditionalOnProperty(name = "orthrus.slave.mode", havingValue = "server", matchIfMissing = true)
public class MasterApiClient {

	private static final Logger log = LoggerFactory.getLogger(MasterApiClient.class);

	private final NodeClient nodeClient;

	public MasterApiClient(OrthrusProperties properties, ScanService scanService, WebClient.Builder webClientBuilder) {
		String configuredId = properties.getSlave().getId();
		String slaveId = (configuredId != null && !configuredId.trim().isEmpty()) ? configuredId
				: UUID.randomUUID().toString();
		this.nodeClient = new NodeClient(webClientBuilder, properties.getMaster().getUrl(),
				properties.getMaster().getInternalToken(), slaveId, properties.getSlave().getAdvertisedUrl(),
				capabilitiesOf(scanService));
	}

	private static String capabilitiesOf(ScanService scanService) {
		String families = scanService.getAvailableScannerObjects()
			.stream()
			.map((s) -> s.getFamily().name())
			.distinct()
			.collect(Collectors.joining(","));
		String scanners = scanService.getAvailableScannerObjects()
			.stream()
			.map((s) -> s.getId())
			.collect(Collectors.joining(","));
		return String.join(",", scanService.getAvailableDiscoverers()) + "," + scanners + "," + families;
	}

	/**
	 * Registers with the master once the context is ready, and again whenever a heartbeat
	 * is rejected, so the node re-appears after the master restarts.
	 */
	@EventListener(ApplicationReadyEvent.class)
	public void registerToMaster() {
		this.nodeClient.register();
	}

	/**
	 * Publishes the current load and heartbeats the node.
	 * @param activeTasks the number of tasks currently running
	 */
	public void reportLoad(int activeTasks) {
		this.nodeClient.reportLoad(activeTasks);
	}

	@Scheduled(fixedDelayString = "${orthrus.master.heartbeat-interval-ms:10000}")
	public void sendHeartbeat() {
		this.nodeClient.heartbeat();
	}

	/**
	 * Marks the node offline as it shuts down.
	 */
	public void markOffline() {
		this.nodeClient.markOffline();
	}

	/**
	 * Sends a batch of attempts produced by a task. A lost batch fails the task, so the
	 * error propagates.
	 * @param taskId the task the attempts belong to
	 * @param batch the attempts
	 * @return completion signal
	 */
	public Mono<Void> sendTaskAttemptsBatch(Long taskId, List<ScanAttempt> batch) {
		return this.nodeClient.sendTaskAttemptsBatch(taskId, batch);
	}

	/**
	 * Signals a task completed.
	 * @param taskId the task
	 * @param startTime when it started
	 * @param testsCount tests executed
	 * @param vulnsCount vulnerabilities found
	 * @return completion signal
	 */
	public Mono<Void> completeTask(Long taskId, Instant startTime, int testsCount, int vulnsCount) {
		return this.nodeClient.completeTask(taskId, startTime, testsCount, vulnsCount)
			.doOnError((e) -> log.error("Failed to send complete task to master: {}", e.getMessage()));
	}

	/**
	 * Signals a task failed.
	 * @param taskId the task
	 * @param reason why it failed
	 * @return completion signal
	 */
	public Mono<Void> failTask(Long taskId, String reason) {
		return this.nodeClient.failTask(taskId, reason)
			.doOnError((e) -> log.error("Failed to send fail task to master: {}", e.getMessage()));
	}

}

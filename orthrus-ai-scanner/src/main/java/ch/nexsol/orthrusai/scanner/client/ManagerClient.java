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

package ch.nexsol.orthrusai.scanner.client;

import java.time.Instant;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import ch.nexsol.orthrus.protocol.node.NodeClient;
import ch.nexsol.orthrus.protocol.node.ScanAttempt;
import ch.nexsol.orthrusai.scanner.config.AiScannerProperties;

/**
 * This node's side of the manager's internal API. The protocol itself lives in the shared
 * {@link NodeClient}; this component adds what is specific to the AI scanner: the
 * capabilities it advertises, when it registers and heartbeats, and the policy that a
 * lost report never fails a task (the agent's findings are already streamed).
 */
@Component
public class ManagerClient {

	private static final Logger log = LoggerFactory.getLogger(ManagerClient.class);

	/**
	 * Capability marker telling the manager this node runs scans with LLM agents. The
	 * manager routes "AI" runs to nodes advertising it, and deterministic runs to nodes
	 * that do not.
	 */
	private static final String AI_EXECUTOR_MARKER = "AI-EXECUTOR";

	private final NodeClient nodeClient;

	public ManagerClient(AiScannerProperties properties, WebClient.Builder webClientBuilder) {
		String capabilities = AI_EXECUTOR_MARKER + "," + String.join(",", properties.getAi().getFamilies());
		this.nodeClient = new NodeClient(webClientBuilder, properties.getMaster().getUrl(),
				properties.getMaster().getInternalToken(), properties.getSlave().getId(),
				properties.getSlave().getAdvertisedUrl(), capabilities);
	}

	/**
	 * Registers with the manager, advertising the families this node runs. Called once
	 * the context is ready and again whenever a heartbeat is rejected, so the node
	 * re-appears after the manager restarts or after starting before the manager is up.
	 */
	@EventListener(ApplicationReadyEvent.class)
	public void registerToManager() {
		this.nodeClient.register();
	}

	/**
	 * Publishes the current load and heartbeats the node.
	 * @param activeTaskCount the number of tasks currently running
	 */
	public void reportLoad(int activeTaskCount) {
		this.nodeClient.reportLoad(activeTaskCount);
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
	 * Sends a batch of attempts produced by a task.
	 * @param taskId the task the attempts belong to
	 * @param batch the attempts
	 * @return completion signal
	 */
	public Mono<Void> sendTaskAttemptsBatch(Long taskId, List<ScanAttempt> batch) {
		return this.nodeClient.sendTaskAttemptsBatch(taskId, batch).onErrorResume((e) -> {
			log.warn("Could not send attempts for task {}: {}", taskId, e.getMessage());
			return Mono.empty();
		});
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
		return this.nodeClient.completeTask(taskId, startTime, testsCount, vulnsCount).onErrorResume((e) -> {
			log.warn("Could not complete task {}: {}", taskId, e.getMessage());
			return Mono.empty();
		});
	}

	/**
	 * Signals a task failed.
	 * @param taskId the task
	 * @param reason why it failed
	 * @return completion signal
	 */
	public Mono<Void> failTask(Long taskId, String reason) {
		return this.nodeClient.failTask(taskId, reason).onErrorResume((e) -> {
			log.warn("Could not fail task {}: {}", taskId, e.getMessage());
			return Mono.empty();
		});
	}

}

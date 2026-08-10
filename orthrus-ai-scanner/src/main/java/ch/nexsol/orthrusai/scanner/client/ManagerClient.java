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

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import ch.nexsol.orthrusai.scanner.config.AiScannerProperties;
import ch.nexsol.orthrusai.scanner.wire.CompleteTaskRequest;
import ch.nexsol.orthrusai.scanner.wire.FailTaskRequest;
import ch.nexsol.orthrusai.scanner.wire.ScanAttempt;
import ch.nexsol.orthrusai.scanner.wire.SlaveRegistration;

/**
 * Talks to the orthrus manager's internal API. This is the autonomous equivalent of a
 * regular worker's master client: it registers this node, heartbeats its load, and
 * streams task results back. It shares no code with the other orthrus modules, only the
 * JSON contract.
 */
@Component
public class ManagerClient {

	private static final Logger log = LoggerFactory.getLogger(ManagerClient.class);

	private static final String INTERNAL_TOKEN_HEADER = "X-Orthrus-Internal-Token";

	private final WebClient webClient;

	private final String masterUrl;

	private final String slaveId;

	private final String slaveUrl;

	private final String capabilities;

	private final AtomicInteger activeTasks = new AtomicInteger();

	public ManagerClient(AiScannerProperties properties, WebClient.Builder webClientBuilder) {
		this.masterUrl = properties.getMaster().getUrl();
		this.slaveId = properties.getSlave().getId();
		this.slaveUrl = properties.getSlave().getAdvertisedUrl();
		this.capabilities = String.join(",", properties.getAi().getFamilies());
		this.webClient = webClientBuilder
			.defaultHeader(INTERNAL_TOKEN_HEADER, properties.getMaster().getInternalToken())
			.build();
	}

	/**
	 * Registers with the manager once the context is ready, advertising the families this
	 * node runs.
	 */
	@EventListener(ApplicationReadyEvent.class)
	public void registerToManager() {
		SlaveRegistration registration = new SlaveRegistration(this.slaveId, this.slaveUrl, this.capabilities);
		this.webClient.post()
			.uri(this.masterUrl + "/api/internal/slaves/register")
			.bodyValue(registration)
			.retrieve()
			.bodyToMono(Void.class)
			.timeout(Duration.ofSeconds(10))
			.doOnSuccess((v) -> log.info("Registered AI scanner node '{}' with capabilities [{}]", this.slaveId,
					this.capabilities))
			.onErrorResume((e) -> {
				log.warn("Could not register with manager at {}: {}", this.masterUrl, e.getMessage());
				return Mono.empty();
			})
			.subscribe();
	}

	/**
	 * Publishes the current load and heartbeats the node.
	 * @param activeTaskCount the number of tasks currently running
	 */
	public void reportLoad(int activeTaskCount) {
		this.activeTasks.set(activeTaskCount);
		sendHeartbeat();
	}

	@Scheduled(fixedDelayString = "${orthrus.master.heartbeat-interval-ms:10000}")
	public void sendHeartbeat() {
		this.webClient.post()
			.uri(this.masterUrl + "/api/internal/slaves/{id}/heartbeat?activeTasks={n}&url={url}", this.slaveId,
					this.activeTasks.get(), this.slaveUrl)
			.retrieve()
			.bodyToMono(Void.class)
			.timeout(Duration.ofSeconds(5))
			.onErrorResume((e) -> {
				log.debug("Heartbeat failed: {}", e.getMessage());
				return Mono.empty();
			})
			.subscribe();
	}

	/**
	 * Marks the node offline as it shuts down.
	 */
	public void markOffline() {
		this.webClient.post()
			.uri(this.masterUrl + "/api/internal/slaves/" + this.slaveId + "/offline")
			.retrieve()
			.bodyToMono(Void.class)
			.timeout(Duration.ofSeconds(5))
			.onErrorResume((e) -> Mono.empty())
			.subscribe();
	}

	/**
	 * Sends a batch of attempts produced by a task.
	 * @param taskId the task the attempts belong to
	 * @param batch the attempts
	 * @return completion signal
	 */
	public Mono<Void> sendTaskAttemptsBatch(Long taskId, List<ScanAttempt> batch) {
		return this.webClient.post()
			.uri(this.masterUrl + "/api/internal/tasks/" + taskId + "/attempts")
			.bodyValue(batch)
			.retrieve()
			.bodyToMono(Void.class)
			.timeout(Duration.ofSeconds(15))
			.onErrorResume((e) -> {
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
		CompleteTaskRequest request = new CompleteTaskRequest(startTime, Instant.now(), testsCount, vulnsCount);
		return this.webClient.post()
			.uri(this.masterUrl + "/api/internal/tasks/" + taskId + "/complete")
			.bodyValue(request)
			.retrieve()
			.bodyToMono(Void.class)
			.timeout(Duration.ofSeconds(10))
			.onErrorResume((e) -> {
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
		return this.webClient.post()
			.uri(this.masterUrl + "/api/internal/tasks/" + taskId + "/fail")
			.bodyValue(new FailTaskRequest(reason))
			.retrieve()
			.bodyToMono(Void.class)
			.timeout(Duration.ofSeconds(10))
			.onErrorResume((e) -> {
				log.warn("Could not fail task {}: {}", taskId, e.getMessage());
				return Mono.empty();
			});
	}

}

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

package ch.nexsol.orthrus.protocol.node;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

/**
 * The node side of the manager's internal API: registration, heartbeat and task
 * reporting. Every kind of node (deterministic worker, AI scanner) speaks this exact
 * protocol, so it lives here once. Lifecycle wiring (when to register, how often to
 * heartbeat) stays with the node, which calls {@link #register()} and
 * {@link #heartbeat()} from its own scheduling.
 */
public class NodeClient {

	private static final Logger log = LoggerFactory.getLogger(NodeClient.class);

	/**
	 * Header carrying the shared secret the manager expects on every internal call.
	 */
	public static final String INTERNAL_TOKEN_HEADER = "X-Orthrus-Internal-Token";

	private static final Duration REGISTER_TIMEOUT = Duration.ofSeconds(10);

	private static final Duration HEARTBEAT_TIMEOUT = Duration.ofSeconds(5);

	private static final Duration REPORT_TIMEOUT = Duration.ofSeconds(15);

	private final WebClient webClient;

	private final String managerUrl;

	private final String nodeId;

	private final String advertisedUrl;

	private final String capabilities;

	private final AtomicInteger activeTasks = new AtomicInteger();

	private final AtomicBoolean registering = new AtomicBoolean();

	private volatile boolean managerDownLogged;

	/**
	 * @param webClientBuilder the client builder to derive the manager client from
	 * @param managerUrl the manager's base URL
	 * @param internalToken the shared secret sent on every call
	 * @param nodeId this node's stable identifier
	 * @param advertisedUrl the URL the manager should dispatch tasks to
	 * @param capabilities the comma-separated capabilities to advertise
	 */
	public NodeClient(WebClient.Builder webClientBuilder, String managerUrl, String internalToken, String nodeId,
			String advertisedUrl, String capabilities) {
		this.webClient = webClientBuilder.clone().defaultHeader(INTERNAL_TOKEN_HEADER, internalToken).build();
		this.managerUrl = managerUrl;
		this.nodeId = nodeId;
		this.advertisedUrl = advertisedUrl;
		this.capabilities = capabilities;
	}

	public String nodeId() {
		return this.nodeId;
	}

	/**
	 * Registers the node with the manager. A registration already in flight is not
	 * duplicated: the startup registration and a heartbeat-triggered re-registration can
	 * otherwise race. Failures are logged once until the manager is reachable again, so a
	 * manager that is down does not flood the log at every heartbeat.
	 */
	public void register() {
		if (!this.registering.compareAndSet(false, true)) {
			log.debug("Registration already in flight; skipping.");
			return;
		}
		SlaveRegistration registration = new SlaveRegistration(this.nodeId, this.advertisedUrl, this.capabilities);
		this.webClient.post()
			.uri(this.managerUrl + "/api/internal/slaves/register")
			.bodyValue(registration)
			.retrieve()
			.bodyToMono(Void.class)
			.timeout(REGISTER_TIMEOUT)
			.doFinally((signal) -> this.registering.set(false))
			.subscribe((v) -> {
			}, (e) -> {
				if (!this.managerDownLogged) {
					log.warn("Could not register node '{}' with manager at {}: {}", this.nodeId, this.managerUrl,
							e.getMessage());
					this.managerDownLogged = true;
				}
				else {
					log.debug("Could not register node '{}' with manager at {}: {}", this.nodeId, this.managerUrl,
							e.getMessage());
				}
			}, () -> {
				if (this.managerDownLogged) {
					log.info("Reconnected and registered node '{}' with manager", this.nodeId);
					this.managerDownLogged = false;
				}
				else {
					log.info("Registered node '{}' with capabilities [{}]", this.nodeId, this.capabilities);
				}
			});
	}

	/**
	 * Records the number of tasks in flight and pushes it to the manager right away.
	 * @param activeTaskCount the tasks currently running on this node
	 */
	public void reportLoad(int activeTaskCount) {
		this.activeTasks.set(activeTaskCount);
		heartbeat();
	}

	/**
	 * Sends the periodic heartbeat. A rejected heartbeat means the manager does not know
	 * this node (it restarted, or came up after the node), so the node re-registers.
	 */
	public void heartbeat() {
		this.webClient.post()
			.uri(this.managerUrl + "/api/internal/slaves/{id}/heartbeat?activeTasks={n}&url={url}", this.nodeId,
					this.activeTasks.get(), this.advertisedUrl)
			.retrieve()
			.bodyToMono(Void.class)
			.timeout(HEARTBEAT_TIMEOUT)
			.subscribe((v) -> {
			}, (e) -> {
				if (!this.managerDownLogged) {
					log.warn("Heartbeat failed ({}). Attempting to re-register...", e.getMessage());
				}
				else {
					log.debug("Heartbeat failed ({}). Attempting to re-register...", e.getMessage());
				}
				register();
			});
	}

	/**
	 * Tells the manager this node is going away, best effort.
	 */
	public void markOffline() {
		this.activeTasks.set(0);
		this.webClient.post()
			.uri(this.managerUrl + "/api/internal/slaves/" + this.nodeId + "/offline")
			.retrieve()
			.bodyToMono(Void.class)
			.timeout(HEARTBEAT_TIMEOUT)
			.subscribe((v) -> log.debug("Manager notified of shutdown"),
					(e) -> log.debug("Could not notify manager of shutdown: {}", e.getMessage()));
	}

	/**
	 * Streams a batch of attempts for a task. Errors propagate so the caller decides
	 * whether a lost batch fails the task.
	 * @param taskId the task the attempts belong to
	 * @param batch the attempts
	 * @return completion signal
	 */
	public Mono<Void> sendTaskAttemptsBatch(Long taskId, List<ScanAttempt> batch) {
		return this.webClient.post()
			.uri(this.managerUrl + "/api/internal/tasks/" + taskId + "/attempts")
			.bodyValue(batch)
			.retrieve()
			.bodyToMono(Void.class)
			.timeout(REPORT_TIMEOUT);
	}

	/**
	 * Reports a task as completed.
	 * @param taskId the task
	 * @param startTime when the node started it
	 * @param testsCount the attempts executed
	 * @param vulnsCount the vulnerabilities found
	 * @return completion signal
	 */
	public Mono<Void> completeTask(Long taskId, Instant startTime, int testsCount, int vulnsCount) {
		CompleteTaskRequest request = new CompleteTaskRequest(startTime, Instant.now(), testsCount, vulnsCount);
		return this.webClient.post()
			.uri(this.managerUrl + "/api/internal/tasks/" + taskId + "/complete")
			.bodyValue(request)
			.retrieve()
			.bodyToMono(Void.class)
			.timeout(REPORT_TIMEOUT);
	}

	/**
	 * Reports a task as failed.
	 * @param taskId the task
	 * @param reason a short cause
	 * @return completion signal
	 */
	public Mono<Void> failTask(Long taskId, String reason) {
		return this.webClient.post()
			.uri(this.managerUrl + "/api/internal/tasks/" + taskId + "/fail")
			.bodyValue(new FailTaskRequest(reason))
			.retrieve()
			.bodyToMono(Void.class)
			.timeout(REPORT_TIMEOUT);
	}

}

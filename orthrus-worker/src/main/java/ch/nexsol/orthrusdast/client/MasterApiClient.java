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
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.http.MediaType;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import ch.nexsol.orthrusdast.config.OrthrusProperties;
import ch.nexsol.orthrusdast.engine.ScanService;
import ch.nexsol.orthrusdast.model.ScanAttempt;

/**
 * Talks to the master on behalf of this worker node. The node reports how many tasks it
 * is running and the master derives the node status from it.
 */
@Component
@EnableScheduling
@ConditionalOnProperty(name = "orthrus.slave.mode", havingValue = "server", matchIfMissing = true)
public class MasterApiClient {

	private static final Logger log = LoggerFactory.getLogger(MasterApiClient.class);

	private final WebClient webClient;

	private final String masterUrl;

	private final String slaveId;

	private final String slaveUrl;

	private final AtomicInteger activeTaskCount = new AtomicInteger();

	private final AtomicBoolean registering = new AtomicBoolean();

	private boolean masterDownLogged = false;

	private final ScanService scanService;

	public MasterApiClient(OrthrusProperties properties, ScanService scanService) {
		this.scanService = scanService;
		this.webClient = WebClient.builder()
			.defaultHeader("X-Orthrus-Internal-Token", properties.getMaster().getInternalToken())
			.build();
		this.masterUrl = properties.getMaster().getUrl();
		String configuredId = properties.getSlave().getId();
		this.slaveId = (configuredId != null && !configuredId.trim().isEmpty()) ? configuredId
				: UUID.randomUUID().toString();
		this.slaveUrl = properties.getSlave().getAdvertisedUrl();
	}

	/**
	 * Announces this node to the master. Called on startup and again whenever a heartbeat
	 * is rejected; the guard keeps those two from registering at the same time.
	 */
	@EventListener(ApplicationReadyEvent.class)
	public void registerToMaster() {
		if (!this.registering.compareAndSet(false, true)) {
			log.debug("Registration already in flight; skipping.");
			return;
		}

		String families = this.scanService.getAvailableScannerObjects()
			.stream()
			.map((s) -> s.getFamily().name())
			.distinct()
			.collect(Collectors.joining(","));
		String caps = String.join(",", this.scanService.getAvailableDiscoverers()) + ","
				+ this.scanService.getAvailableScannerObjects()
					.stream()
					.map((s) -> s.getId())
					.collect(Collectors.joining(","))
				+ "," + families;
		String payload = String.format("{\"id\": \"%s\", \"url\": \"%s\", \"capabilities\": \"%s\"}", this.slaveId,
				this.slaveUrl, caps);
		if (!this.masterDownLogged) {
			log.info("Registering slave to master at {}", this.masterUrl);
		}
		else {
			log.debug("Registering slave to master at {}", this.masterUrl);
		}

		this.webClient.post()
			.uri(this.masterUrl + "/api/internal/slaves/register")
			.contentType(MediaType.APPLICATION_JSON)
			.bodyValue(payload)
			.retrieve()
			.bodyToMono(Void.class)
			.doFinally((signal) -> this.registering.set(false))
			.subscribe((success) -> {
				if (this.masterDownLogged) {
					log.info("Successfully reconnected and registered to master with ID: {}", this.slaveId);
					this.masterDownLogged = false;
				}
				else {
					log.info("Successfully registered to master with ID: {}", this.slaveId);
				}
			}, (error) -> {
				if (!this.masterDownLogged) {
					log.warn("Failed to register to master: {}", error.getMessage());
					this.masterDownLogged = true;
				}
				else {
					log.debug("Failed to register to master: {}", error.getMessage());
				}
			});
	}

	/**
	 * Records how many tasks this node is running and pushes the figure to the master
	 * immediately, rather than waiting for the next heartbeat.
	 * @param activeTasks the number of tasks currently executing on this node
	 */
	public void reportLoad(int activeTasks) {
		this.activeTaskCount.set(activeTasks);
		sendHeartbeat();
	}

	@Scheduled(fixedDelayString = "${orthrus.master.heartbeat-interval-ms:10000}")
	public void sendHeartbeat() {
		this.webClient.post()
			.uri(this.masterUrl + "/api/internal/slaves/" + this.slaveId + "/heartbeat?activeTasks="
					+ this.activeTaskCount.get() + "&url=" + this.slaveUrl)
			.retrieve()
			.bodyToMono(Void.class)
			.subscribe((success) -> {
				if (this.masterDownLogged) {
					log.info("Heartbeat successful. Master is back online.");
					this.masterDownLogged = false;
				}
			}, (error) -> {
				if (!this.masterDownLogged) {
					log.warn("Heartbeat failed ({}). Attempting to re-register...", error.getMessage());
				}
				else {
					log.debug("Heartbeat failed ({}). Attempting to re-register...", error.getMessage());
				}
				registerToMaster();
			});
	}

	/**
	 * Tells the master this node is going away, so no further work is dispatched to it.
	 */
	public void markOffline() {
		this.activeTaskCount.set(0);
		this.webClient.post()
			.uri(this.masterUrl + "/api/internal/slaves/" + this.slaveId + "/offline")
			.retrieve()
			.bodyToMono(Void.class)
			.subscribe((success) -> log.debug("Master notified of shutdown"),
					(error) -> log.debug("Could not notify master of shutdown: {}", error.getMessage()));
	}

	public Mono<Void> sendTaskAttemptsBatch(Long taskId, List<ScanAttempt> batch) {
		return this.webClient.post()
			.uri(this.masterUrl + "/api/internal/tasks/" + taskId + "/attempts")
			.contentType(MediaType.APPLICATION_JSON)
			.bodyValue(batch)
			.retrieve()
			.bodyToMono(Void.class);
	}

	public Mono<Void> completeTask(Long taskId, Instant startTime, int testsCount, int vulnsCount) {
		String payload = String.format(
				"{\"startTime\": \"%s\", \"endTime\": \"%s\", \"testsCount\": %d, \"vulnsCount\": %d}",
				startTime.toString(), Instant.now().toString(), testsCount, vulnsCount);
		return this.webClient.post()
			.uri(this.masterUrl + "/api/internal/tasks/" + taskId + "/complete")
			.contentType(MediaType.APPLICATION_JSON)
			.bodyValue(payload)
			.retrieve()
			.bodyToMono(Void.class)
			.doOnError((e) -> log.error("Failed to send complete task to master: {}", e.getMessage()));
	}

	public Mono<Void> failTask(Long taskId, String reason) {
		String payload = String.format("{\"reason\": \"%s\"}", reason.replace("\"", "\\\""));
		return this.webClient.post()
			.uri(this.masterUrl + "/api/internal/tasks/" + taskId + "/fail")
			.contentType(MediaType.APPLICATION_JSON)
			.bodyValue(payload)
			.retrieve()
			.bodyToMono(Void.class)
			.doOnError((e) -> log.error("Failed to send fail task to master: {}", e.getMessage()));
	}

}

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
import ch.nexsol.orthrusdast.model.NodeStatus;
import ch.nexsol.orthrusdast.model.ScanAttempt;

@Component
@EnableScheduling
@ConditionalOnProperty(name = "orthrus.slave.mode", havingValue = "server", matchIfMissing = true)
public class MasterApiClient {

	private final WebClient webClient;

	private final String masterUrl;

	private final String slaveId;

	private final String slaveUrl;

	private NodeStatus currentStatus = NodeStatus.IDLE;

	private static final Logger log = LoggerFactory.getLogger(MasterApiClient.class);

	private boolean masterDownLogged = false;

	public MasterApiClient(OrthrusProperties properties) {
		this.webClient = WebClient.builder()
			.defaultHeader("X-Orthrus-Internal-Token", properties.getMaster().getInternalToken())
			.build();
		this.masterUrl = properties.getMaster().getUrl();
		String configuredId = properties.getSlave().getId();
		this.slaveId = (configuredId != null && !configuredId.trim().isEmpty()) ? configuredId
				: UUID.randomUUID().toString();
		this.slaveUrl = properties.getSlave().getAdvertisedUrl();
	}

	@EventListener(ApplicationReadyEvent.class)
	public void registerToMaster() {
		String payload = String.format("{\"id\": \"%s\", \"url\": \"%s\"}", slaveId, slaveUrl);
		if (!masterDownLogged) {
			log.info("Registering slave to master at {}", masterUrl);
		}
		else {
			log.debug("Registering slave to master at {}", masterUrl);
		}

		webClient.post()
			.uri(masterUrl + "/api/internal/slaves/register")
			.contentType(MediaType.APPLICATION_JSON)
			.bodyValue(payload)
			.retrieve()
			.bodyToMono(Void.class)
			.subscribe((success) -> {
				if (masterDownLogged) {
					log.info("Successfully reconnected and registered to master with ID: {}", slaveId);
					masterDownLogged = false;
				}
				else {
					log.info("Successfully registered to master with ID: {}", slaveId);
				}
			}, (error) -> {
				if (!masterDownLogged) {
					log.warn("Failed to register to master: {}", error.getMessage());
					masterDownLogged = true;
				}
				else {
					log.debug("Failed to register to master: {}", error.getMessage());
				}
			});
	}

	@Scheduled(fixedDelayString = "${orthrus.master.heartbeat-interval-ms:10000}")
	public void sendHeartbeat() {
		webClient.post()
			.uri(masterUrl + "/api/internal/slaves/" + slaveId + "/heartbeat?status=" + currentStatus + "&url="
					+ slaveUrl)
			.retrieve()
			.bodyToMono(Void.class)
			.subscribe((success) -> {
				if (masterDownLogged) {
					log.info("Heartbeat successful. Master is back online.");
					masterDownLogged = false;
				}
			}, (error) -> {
				if (!masterDownLogged) {
					log.warn("Heartbeat failed ({}). Attempting to re-register...", error.getMessage());
				}
				else {
					log.debug("Heartbeat failed ({}). Attempting to re-register...", error.getMessage());
				}
				registerToMaster();
			});
	}

	public Mono<Void> sendJobAttemptsBatch(Long jobId, List<ScanAttempt> batch) {
		return webClient.post()
			.uri(masterUrl + "/api/internal/jobs/" + jobId + "/attempts")
			.contentType(MediaType.APPLICATION_JSON)
			.bodyValue(batch)
			.retrieve()
			.bodyToMono(Void.class);
	}

	public Mono<Void> completeJob(Long jobId, Instant startTime) {
		// We only send the startTime and endTime. The Master will calculate totals from
		// the batches it received.
		String payload = String.format("{\"startTime\": \"%s\", \"endTime\": \"%s\"}", startTime.toString(),
				Instant.now().toString());
		return webClient.post()
			.uri(masterUrl + "/api/internal/jobs/" + jobId + "/complete")
			.contentType(MediaType.APPLICATION_JSON)
			.bodyValue(payload)
			.retrieve()
			.bodyToMono(Void.class)
			.doOnSuccess((v) -> setStatus(NodeStatus.IDLE))
			.doOnError((e) -> {
				log.error("Failed to send complete job to master: {}", e.getMessage());
				setStatus(NodeStatus.IDLE);
			});
	}

	public Mono<Void> failJob(Long jobId, String reason) {
		String payload = String.format("{\"reason\": \"%s\"}", reason.replace("\"", "\\\""));
		return webClient.post()
			.uri(masterUrl + "/api/internal/jobs/" + jobId + "/fail")
			.contentType(MediaType.APPLICATION_JSON)
			.bodyValue(payload)
			.retrieve()
			.bodyToMono(Void.class)
			.doOnSuccess((v) -> setStatus(NodeStatus.IDLE))
			.doOnError((e) -> {
				log.error("Failed to send fail job to master: {}", e.getMessage());
				setStatus(NodeStatus.IDLE);
			});
	}

	public Mono<Void> sendTaskAttemptsBatch(Long taskId, List<ScanAttempt> batch) {
		return webClient.post()
			.uri(masterUrl + "/api/internal/tasks/" + taskId + "/attempts")
			.contentType(MediaType.APPLICATION_JSON)
			.bodyValue(batch)
			.retrieve()
			.bodyToMono(Void.class);
	}

	public Mono<Void> completeTask(Long taskId, Instant startTime, int testsCount, int vulnsCount) {
		String payload = String.format(
				"{\"startTime\": \"%s\", \"endTime\": \"%s\", \"testsCount\": %d, \"vulnsCount\": %d}",
				startTime.toString(), Instant.now().toString(), testsCount, vulnsCount);
		return webClient.post()
			.uri(masterUrl + "/api/internal/tasks/" + taskId + "/complete")
			.contentType(MediaType.APPLICATION_JSON)
			.bodyValue(payload)
			.retrieve()
			.bodyToMono(Void.class)
			.doOnSuccess((v) -> setStatus(NodeStatus.IDLE))
			.doOnError((e) -> {
				log.error("Failed to send complete task to master: {}", e.getMessage());
				setStatus(NodeStatus.IDLE);
			});
	}

	public Mono<Void> failTask(Long taskId, String reason) {
		String payload = String.format("{\"reason\": \"%s\"}", reason.replace("\"", "\\\""));
		return webClient.post()
			.uri(masterUrl + "/api/internal/tasks/" + taskId + "/fail")
			.contentType(MediaType.APPLICATION_JSON)
			.bodyValue(payload)
			.retrieve()
			.bodyToMono(Void.class)
			.doOnSuccess((v) -> setStatus(NodeStatus.IDLE))
			.doOnError((e) -> {
				log.error("Failed to send fail task to master: {}", e.getMessage());
				setStatus(NodeStatus.IDLE);
			});
	}

	public void setStatus(NodeStatus status) {
		this.currentStatus = status;
	}

}

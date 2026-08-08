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

package ch.nexsol.orthrusdast.api;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import ch.nexsol.orthrusdast.auth.OAuth2TokenFetcher;
import ch.nexsol.orthrusdast.entity.ScanJobEntity;
import ch.nexsol.orthrusdast.ingestion.EndpointDiscoverer;
import ch.nexsol.orthrusdast.model.GatewayType;
import ch.nexsol.orthrusdast.model.JobStatus;
import ch.nexsol.orthrusdast.model.NodeStatus;
import ch.nexsol.orthrusdast.model.OAuth2Config;
import ch.nexsol.orthrusdast.model.ScanConfiguration;
import ch.nexsol.orthrusdast.model.SecurityScheme;
import ch.nexsol.orthrusdast.repository.ScanJobRepository;
import ch.nexsol.orthrusdast.repository.SlaveNodeRepository;

/**
 * Reactive REST Controller for triggering scans via HTTP.
 */
@RestController
@RequestMapping("/api/v1/scans")
public class ScanController {

	private static final Logger log = LoggerFactory.getLogger(ScanController.class);

	private final OAuth2TokenFetcher tokenFetcher;

	private final ScanJobRepository scanJobRepository;

	private final tools.jackson.databind.ObjectMapper objectMapper;

	private final SlaveNodeRepository slaveNodeRepository;

	/**
	 * Workers advertise discoverers and scanners in a single flat capability string; the
	 * discoverer ids are recovered by intersecting it with the discoverers on the
	 * classpath.
	 */
	private final Set<String> knownDiscovererIds;

	public ScanController(OAuth2TokenFetcher tokenFetcher, ScanJobRepository scanJobRepository,
			tools.jackson.databind.ObjectMapper objectMapper, SlaveNodeRepository slaveNodeRepository,
			List<EndpointDiscoverer> discoverers) {
		this.tokenFetcher = tokenFetcher;
		this.scanJobRepository = scanJobRepository;
		this.objectMapper = objectMapper;
		this.slaveNodeRepository = slaveNodeRepository;
		this.knownDiscovererIds = discoverers.stream().map(EndpointDiscoverer::getId).collect(Collectors.toSet());
	}

	/**
	 * Lists the discoverers the connected worker fleet provides.
	 * @return the discoverer ids currently runnable
	 */
	@GetMapping("/discoverers")
	public Mono<List<String>> getDiscoverers() {
		return this.slaveNodeRepository.findAll()
			.filter((slave) -> Boolean.TRUE.equals(slave.getIsActive()))
			.filter((slave) -> slave.getStatus() != NodeStatus.OFFLINE)
			.filter((slave) -> slave.getCapabilities() != null)
			.flatMap((slave) -> Flux.fromArray(slave.getCapabilities().split(",")))
			.map(String::trim)
			.filter(this.knownDiscovererIds::contains)
			.distinct()
			.sort()
			.collectList();
	}

	/**
	 * Queues a new scan. The scan itself runs asynchronously on a worker node, so this
	 * returns the id of the created job — poll it or subscribe to its SSE stream to
	 * follow progress.
	 * @param request the scan request
	 * @return 202 with the queued job's id
	 */
	@PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
	public Mono<ResponseEntity<ScanJobAccepted>> triggerScan(@RequestBody ScanRequest request) {

		return Mono.justOrEmpty(request.oauth2())
			.flatMap((oauth2Config) -> this.tokenFetcher.fetchTokens(oauth2Config))
			.defaultIfEmpty(List.of())
			.flatMap((fetchedTokens) -> {
				SecurityScheme authScheme = request.authScheme();
				SecurityScheme secondaryAuthScheme = request.secondaryAuthScheme();

				if (!fetchedTokens.isEmpty()) {
					authScheme = fetchedTokens.get(0);
					if (fetchedTokens.size() > 1) {
						secondaryAuthScheme = fetchedTokens.get(1);
					}
				}

				ScanConfiguration config = new ScanConfiguration(
						(request.includeScanners() != null) ? request.includeScanners() : List.of(),
						(request.excludeScanners() != null) ? request.excludeScanners() : List.of(),
						(request.concurrency() > 0) ? request.concurrency() : 10, 5000, 10000,
						request.ignoreSslErrors(), "json", authScheme, secondaryAuthScheme,
						(request.language() != null) ? request.language() : "en",
						(request.includePassed() != null) ? request.includePassed() : false, GatewayType.AUTO, null,
						null, request.oauth2(), request.overrideHost());

				return Mono.fromCallable(() -> this.objectMapper.writeValueAsString(config)).flatMap((configJson) -> {
					ScanJobEntity job = new ScanJobEntity(request.discovererId(), request.target(), configJson,
							JobStatus.PENDING, null);
					return this.scanJobRepository.save(job);
				})
					.map((savedJob) -> ResponseEntity.accepted()
						.body(new ScanJobAccepted(savedJob.getId(), savedJob.getTarget(), savedJob.getStatus(),
								"/scans/" + savedJob.getId() + "/stream")))
					.doOnError(
							(e) -> log.error("Failed to create or save scan job for target: {}", request.target(), e));
			})
			.onErrorResume(IllegalArgumentException.class, (e) -> Mono.just(ResponseEntity.badRequest().build()))
			.onErrorResume(Exception.class,
					(e) -> Mono.just(ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build()));
	}

	// DTO for incoming requests
	public record ScanRequest(String discovererId, // e.g. 'openapi', 'blackbox', 'curl'
			String target, String overrideHost, List<String> includeScanners, List<String> excludeScanners,
			int concurrency, boolean ignoreSslErrors, SecurityScheme authScheme, SecurityScheme secondaryAuthScheme,
			OAuth2Config oauth2, String language, Boolean includePassed) {
	}

	/**
	 * Returned on acceptance so callers can follow the queued scan.
	 */
	public record ScanJobAccepted(Long jobId, String target, JobStatus status, String eventStreamUrl) {
	}

}

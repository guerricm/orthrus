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

package ch.nexsol.orthrusai.scanner.scan;

import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import tools.jackson.databind.ObjectMapper;

import ch.nexsol.orthrus.protocol.ai.AiScanContext;
import ch.nexsol.orthrus.protocol.ai.Credential;
import ch.nexsol.orthrus.protocol.ai.Endpoint;
import ch.nexsol.orthrus.protocol.node.AttemptStatus;
import ch.nexsol.orthrus.protocol.node.ScanAttempt;
import ch.nexsol.orthrus.protocol.node.ScanTaskRequest;
import ch.nexsol.orthrus.protocol.node.Vulnerability;
import ch.nexsol.orthrusai.scanner.ai.FamilyAgent;
import ch.nexsol.orthrusai.scanner.ai.ProbeConfig;
import ch.nexsol.orthrusai.scanner.config.AiScannerProperties;
import ch.nexsol.orthrusai.scanner.recon.ReconService;

/**
 * The AI executor: recon the target, then run the task's family agent against each
 * discovered endpoint. Each endpoint's agent runs on a bounded-elastic worker (the LLM
 * tool-calling loop is blocking), and produces one {@link ScanAttempt}. Active only when
 * {@code orthrus.ai.enabled} is true, replacing the echo executor.
 */
@Component
@ConditionalOnProperty(prefix = "orthrus.ai", name = "enabled", havingValue = "true")
public class LlmScanExecutor implements ScanExecutor {

	private static final Logger log = LoggerFactory.getLogger(LlmScanExecutor.class);

	private static final int ENDPOINT_CONCURRENCY = 3;

	/**
	 * Families that still test something on an endpoint refusing the identity (403):
	 * forged tokens, authorization and method bypasses, and properties of the response
	 * itself (CORS, banners, security headers, transport). The others exercise input
	 * handling a refused request never reaches.
	 */
	private static final Set<String> RUN_WHEN_FORBIDDEN = Set.of("JWT", "BOLA", "CONFIGURATION", "HTTP", "SSL");

	private final ReconService reconService;

	private final FamilyAgent familyAgent;

	private final ObjectMapper objectMapper;

	private final Duration endpointTimeout;

	public LlmScanExecutor(ReconService reconService, FamilyAgent familyAgent, ObjectMapper objectMapper,
			AiScannerProperties properties) {
		this.reconService = reconService;
		this.familyAgent = familyAgent;
		this.objectMapper = objectMapper;
		this.endpointTimeout = Duration.ofSeconds(properties.getAi().getBudget().getEndpointTimeoutSeconds());
	}

	@Override
	public Flux<ScanAttempt> execute(ScanTaskRequest request) {
		return execute(request, Mono.never());
	}

	/**
	 * Probes the endpoints until done or stopped. When the stop signal fires, the agents
	 * still running are interrupted and every endpoint without a verdict is reported as a
	 * NOT_RUN attempt, so the report shows the coverage was partial instead of silently
	 * listing fewer endpoints. The signal bounds the whole task, recon included: a recon
	 * still running when it fires yields no endpoint at all. Once recon is done, probing
	 * is also bounded by the endpoint budget: the time given to one endpoint for each
	 * wave of endpoints probed in parallel, plus one wave of margin for the agents still
	 * finishing their last turn.
	 * @param request the dispatched task
	 * @param stop the task ceiling; subscribed once, so a timer starts when the task does
	 * @return the attempts, one per endpoint
	 */
	@Override
	public Flux<ScanAttempt> execute(ScanTaskRequest request, Mono<?> stop) {
		String family = request.phase();
		Mono<?> budget = stop.cache();
		return recon(request).takeUntilOther(budget).flatMapMany((recon) -> {
			log.info("AI task {} ({}): probing {} endpoint(s){}{}", request.taskId(), family, recon.endpoints().size(),
					recon.shared() ? " from orchestrator recon" : " from local recon",
					recon.probeConfig().credentials().isEmpty() ? "" : " (authenticated)");
			Duration probingBudget = probingBudget(recon.endpoints().size());
			log.info("AI task {} ({}): {} s to probe, {} s per endpoint", request.taskId(), family,
					probingBudget.toSeconds(), this.endpointTimeout.toSeconds());
			Set<Endpoint> done = ConcurrentHashMap.newKeySet();
			Flux<ScanAttempt> probed = Flux.fromIterable(recon.endpoints())
				.flatMap((endpoint) -> scanEndpoint(family, endpoint, recon.context(), recon.probeConfig())
					.doOnNext((attempt) -> done.add(endpoint)), ENDPOINT_CONCURRENCY)
				.takeUntilOther(Mono.firstWithSignal(budget, Mono.delay(probingBudget)));
			Flux<ScanAttempt> notRun = Flux.defer(() -> Flux.fromIterable(recon.endpoints())
				.filter((endpoint) -> !done.contains(endpoint))
				.map((endpoint) -> notRunAttempt(family, endpoint)));
			return probed.concatWith(notRun);
		});
	}

	/**
	 * The time to probe {@code endpoints} endpoints: one endpoint timeout per wave of
	 * parallel agents, plus one wave of margin.
	 * @param endpoints the number of endpoints to probe
	 * @return the probing budget
	 */
	Duration probingBudget(int endpoints) {
		int waves = (endpoints + ENDPOINT_CONCURRENCY - 1) / ENDPOINT_CONCURRENCY;
		return this.endpointTimeout.multipliedBy(waves + 1L);
	}

	private ScanAttempt notRunAttempt(String family, Endpoint endpoint) {
		return new ScanAttempt("ai-" + family.toLowerCase(), "AI " + family + " Agent (not run: task budget spent)",
				endpoint.method(), endpoint.url(), AttemptStatus.NOT_RUN, List.of());
	}

	/**
	 * Resolves the endpoints, context and probe config to scan with. Prefers the
	 * orchestrator's shared recon carried on the task; falls back to this node's own
	 * recon for the endpoints when it is absent, but still applies the credentials and
	 * settings the manager resolved, so authenticated probing works with or without an
	 * orchestrator.
	 * @param request the task
	 * @return the endpoints, shared context and probe config
	 */
	private Mono<Recon> recon(ScanTaskRequest request) {
		AiScanContext shared = parseSharedRecon(request.aiContextJson());
		ProbeConfig probeConfig = probeConfigOf(shared);
		String context = (shared != null) ? shared.context() : null;
		if (shared != null && shared.endpoints() != null && !shared.endpoints().isEmpty()) {
			return Mono.just(new Recon(shared.endpoints(), context, probeConfig, true));
		}
		return this.reconService.discover(request.target())
			.map((endpoints) -> new Recon(endpoints, context, probeConfig, false));
	}

	private ProbeConfig probeConfigOf(AiScanContext shared) {
		if (shared == null) {
			return ProbeConfig.defaults();
		}
		List<Credential> credentials = (shared.credentials() != null) ? shared.credentials() : List.of();
		int readTimeout = (shared.readTimeoutMs() > 0) ? shared.readTimeoutMs() : 10000;
		return new ProbeConfig(credentials, shared.ignoreSslErrors(), readTimeout);
	}

	private AiScanContext parseSharedRecon(String json) {
		if (json == null || json.isBlank()) {
			return null;
		}
		try {
			return this.objectMapper.readValue(json, AiScanContext.class);
		}
		catch (RuntimeException ex) {
			log.warn("Could not parse the orchestrator's shared recon; falling back to local recon: {}",
					ex.getMessage());
			return null;
		}
	}

	/**
	 * Probes one endpoint, after the same gate as the deterministic engine: a baseline
	 * request with the configured credentials. A 401 means they are rejected, so no agent
	 * runs. A 403 means they are accepted but the identity is refused, so only the
	 * families probing a way around the refusal, or the refused response itself, run.
	 * @param family the scanner family name
	 * @param endpoint the endpoint to probe
	 * @param context the orchestrator's shared target fingerprint, may be null
	 * @param probeConfig the credentials, TLS leniency and timeout to apply
	 * @return the endpoint's single attempt
	 */
	private Flux<ScanAttempt> scanEndpoint(String family, Endpoint endpoint, String context, ProbeConfig probeConfig) {
		return this.familyAgent.baselineStatus(endpoint, probeConfig).defaultIfEmpty(0).flatMapMany((status) -> {
			if (status == 401) {
				return Flux.just(attempt(family, endpoint, AttemptStatus.AUTH_ERROR, List.of()));
			}
			boolean refused = status == 403;
			if (refused && !RUN_WHEN_FORBIDDEN.contains(family.toUpperCase(Locale.ROOT))) {
				return Flux.just(attempt(family, endpoint, AttemptStatus.FORBIDDEN, List.of()));
			}
			return Flux.defer(() -> {
				List<Vulnerability> findings = this.familyAgent.scan(family, endpoint, context, probeConfig, refused);
				AttemptStatus verdict = findings.isEmpty() ? AttemptStatus.PASSED : AttemptStatus.FAILED;
				return Flux.just(attempt(family, endpoint, verdict, findings));
			}).subscribeOn(Schedulers.boundedElastic());
		});
	}

	private static ScanAttempt attempt(String family, Endpoint endpoint, AttemptStatus status,
			List<Vulnerability> findings) {
		return new ScanAttempt("ai-" + family.toLowerCase(Locale.ROOT), "AI " + family + " Agent", endpoint.method(),
				endpoint.url(), status, findings);
	}

	private record Recon(List<Endpoint> endpoints, String context, ProbeConfig probeConfig, boolean shared) {
	}

}

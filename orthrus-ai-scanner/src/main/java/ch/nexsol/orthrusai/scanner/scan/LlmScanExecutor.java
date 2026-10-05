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

import java.util.List;

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

	private final ReconService reconService;

	private final FamilyAgent familyAgent;

	private final ObjectMapper objectMapper;

	public LlmScanExecutor(ReconService reconService, FamilyAgent familyAgent, ObjectMapper objectMapper) {
		this.reconService = reconService;
		this.familyAgent = familyAgent;
		this.objectMapper = objectMapper;
	}

	@Override
	public Flux<ScanAttempt> execute(ScanTaskRequest request) {
		String family = request.phase();
		return recon(request).flatMapMany((recon) -> {
			log.info("AI task {} ({}): probing {} endpoint(s){}{}", request.taskId(), family, recon.endpoints().size(),
					recon.shared() ? " from orchestrator recon" : " from local recon",
					recon.probeConfig().credentials().isEmpty() ? "" : " (authenticated)");
			return Flux.fromIterable(recon.endpoints())
				.flatMap((endpoint) -> scanEndpoint(family, endpoint, recon.context(), recon.probeConfig()),
						ENDPOINT_CONCURRENCY);
		});
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

	private Flux<ScanAttempt> scanEndpoint(String family, Endpoint endpoint, String context, ProbeConfig probeConfig) {
		return Flux.defer(() -> {
			List<Vulnerability> findings = this.familyAgent.scan(family, endpoint, context, probeConfig);
			String scannerId = "ai-" + family.toLowerCase();
			AttemptStatus status = findings.isEmpty() ? AttemptStatus.PASSED : AttemptStatus.FAILED;
			ScanAttempt attempt = new ScanAttempt(scannerId, "AI " + family + " Agent", endpoint.method(),
					endpoint.url(), status, findings);
			return Flux.just(attempt);
		}).subscribeOn(Schedulers.boundedElastic());
	}

	private record Recon(List<Endpoint> endpoints, String context, ProbeConfig probeConfig, boolean shared) {
	}

}

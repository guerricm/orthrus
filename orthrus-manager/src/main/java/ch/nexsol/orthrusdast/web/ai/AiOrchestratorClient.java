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

package ch.nexsol.orthrusdast.web.ai;

import java.time.Duration;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import ch.nexsol.orthrus.protocol.ai.Credential;
import ch.nexsol.orthrus.protocol.ai.PlanRequest;
import ch.nexsol.orthrus.protocol.ai.ReconRequest;
import ch.nexsol.orthrus.protocol.ai.ReconResult;
import ch.nexsol.orthrus.protocol.ai.ScanPlan;
import ch.nexsol.orthrus.protocol.node.NodeClient;

/**
 * Calls the AI orchestrator. Present only when {@code orthrus.ai.orchestrator.url} is
 * set, so a manager without an orchestrator still starts and simply offers no AI
 * assistance.
 */
@Component
@ConditionalOnProperty("orthrus.ai.orchestrator.url")
public class AiOrchestratorClient {

	/**
	 * Planning involves a model round-trip.
	 */
	private static final Duration PLAN_TIMEOUT = Duration.ofSeconds(120);

	/**
	 * The orchestrator caps its own recon at 10 seconds and falls back on its own, so
	 * waiting longer only holds the AI job for an orchestrator that is gone.
	 */
	private static final Duration RECON_TIMEOUT = Duration.ofSeconds(15);

	private final WebClient webClient;

	private final String orchestratorUrl;

	/**
	 * @param orchestratorUrl the orchestrator's base URL
	 * @param internalToken the shared secret the orchestrator expects on every call, the
	 * same one the nodes present to the manager
	 * @param webClientBuilder the client builder
	 */
	public AiOrchestratorClient(@Value("${orthrus.ai.orchestrator.url}") String orchestratorUrl,
			@Value("${orthrus.master.internal-token}") String internalToken, WebClient.Builder webClientBuilder) {
		this.orchestratorUrl = orchestratorUrl;
		this.webClient = webClientBuilder.clone()
			.defaultHeader(NodeClient.INTERNAL_TOKEN_HEADER, internalToken)
			.build();
	}

	/**
	 * Asks the orchestrator to plan a scan for a target.
	 * @param target the target to scan
	 * @param objective the operator's objective (may be null)
	 * @param availableDiscoverers the discoverers this manager offers
	 * @return the plan
	 */
	public Mono<ScanPlan> suggestPlan(String target, String objective, List<String> availableDiscoverers) {
		PlanRequest body = new PlanRequest(target, (objective != null) ? objective : "",
				(availableDiscoverers != null) ? availableDiscoverers : List.of());
		return this.webClient.post()
			.uri(this.orchestratorUrl + "/api/v1/plan")
			.bodyValue(body)
			.retrieve()
			.bodyToMono(ScanPlan.class)
			.timeout(PLAN_TIMEOUT);
	}

	/**
	 * Asks the orchestrator to fingerprint a target and map its endpoints, once per AI
	 * job. The credentials and host let it fetch a protected OpenAPI document and resolve
	 * the right base path. The manager persists the result and forwards it to each node.
	 * @param target the target to recon
	 * @param openapiOverrideHost the base host to force, or null
	 * @param credentials the credentials to send while reconning, may be empty
	 * @return the shared recon result
	 */
	public Mono<ReconResult> recon(String target, String openapiOverrideHost, List<Credential> credentials) {
		ReconRequest body = new ReconRequest(target, (openapiOverrideHost != null) ? openapiOverrideHost : "",
				(credentials != null) ? credentials : List.of());
		return this.webClient.post()
			.uri(this.orchestratorUrl + "/api/v1/recon")
			.bodyValue(body)
			.retrieve()
			.bodyToMono(ReconResult.class)
			.timeout(RECON_TIMEOUT);
	}

}

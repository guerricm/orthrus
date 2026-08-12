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
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

/**
 * Thin proxy to the optional AI orchestrator. The manager never depends on the AI module
 * at compile time; it reaches the orchestrator over HTTP only, and only when
 * {@code orthrus.ai.orchestrator.url} is configured. This keeps the AI orchestration a
 * separable add-on.
 */
@Component
@ConditionalOnProperty(prefix = "orthrus.ai.orchestrator", name = "url")
public class AiOrchestratorClient {

	private final WebClient webClient;

	private final String orchestratorUrl;

	public AiOrchestratorClient(@Value("${orthrus.ai.orchestrator.url}") String orchestratorUrl,
			WebClient.Builder webClientBuilder) {
		this.orchestratorUrl = orchestratorUrl;
		this.webClient = webClientBuilder.build();
	}

	/**
	 * Asks the orchestrator to plan and launch a campaign for a target.
	 * @param target the target to scan
	 * @param objective the operator's objective (may be null)
	 * @return the campaign result (plan + launched job)
	 */
	public Mono<CampaignResult> launchCampaign(String target, String objective) {
		Map<String, String> body = Map.of("target", target, "objective", (objective != null) ? objective : "");
		return this.webClient.post()
			.uri(this.orchestratorUrl + "/api/v1/campaigns")
			.bodyValue(body)
			.retrieve()
			.bodyToMono(CampaignResult.class)
			.timeout(Duration.ofSeconds(120));
	}

}

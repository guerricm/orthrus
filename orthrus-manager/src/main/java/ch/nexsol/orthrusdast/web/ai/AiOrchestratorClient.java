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
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

/**
 * Thin proxy to the optional AI orchestrator, which is a pure planning service. The
 * manager asks it for a scan plan and applies the plan itself (pre-fills the Test Plan
 * form, then saves/runs through the normal flow). Active only when
 * {@code orthrus.ai.orchestrator.url} is configured, so the AI is a separable add-on.
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
	 * Asks the orchestrator to plan a scan for a target.
	 * @param target the target to scan
	 * @param objective the operator's objective (may be null)
	 * @param availableDiscoverers the discoverers this manager offers
	 * @return the plan
	 */
	public Mono<ScanPlan> suggestPlan(String target, String objective, List<String> availableDiscoverers) {
		Map<String, Object> body = Map.of("target", target, "objective", (objective != null) ? objective : "",
				"availableDiscoverers", (availableDiscoverers != null) ? availableDiscoverers : List.of());
		return this.webClient.post()
			.uri(this.orchestratorUrl + "/api/v1/plan")
			.bodyValue(body)
			.retrieve()
			.bodyToMono(ScanPlan.class)
			.timeout(Duration.ofSeconds(120));
	}

}

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

package ch.nexsol.orthrusai.orchestrator.plan;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import ch.nexsol.orthrusai.orchestrator.ai.TargetReconTool;
import ch.nexsol.orthrusai.orchestrator.model.ScanPlan;

/**
 * The LLM planner: it fingerprints the target (through a read-only tool) and reasons
 * about which discoverer and scanner families fit, returning a structured
 * {@link ScanPlan}. The discoverer it picks is validated against the fleet's real
 * discoverers so a hallucinated id never reaches the manager. Active only when
 * {@code orthrus.ai.enabled} is true, replacing the static planner.
 */
@Component
@ConditionalOnProperty(prefix = "orthrus.ai", name = "enabled", havingValue = "true")
public class LlmScanPlanner implements ScanPlanner {

	private static final Logger log = LoggerFactory.getLogger(LlmScanPlanner.class);

	private static final String SYSTEM = """
			You are a DAST campaign planner. Given a target and the operator's objective, decide how to \
			scan it. Fingerprint the target first, then choose the single best discoverer id STRICTLY \
			from the provided list of available discoverers, order the scanner families by relevance, \
			and set a sensible concurrency. Explain your choice briefly in the rationale.""";

	private final ChatClient chatClient;

	private final WebClient webClient;

	public LlmScanPlanner(ChatClient orchestratorChatClient, WebClient.Builder webClientBuilder) {
		this.chatClient = orchestratorChatClient;
		this.webClient = webClientBuilder.build();
	}

	@Override
	public ScanPlan plan(String target, String objective, List<String> availableDiscoverers) {
		TargetReconTool reconTool = new TargetReconTool(this.webClient, target);
		String describedObjective = (objective != null) ? objective : "general assessment";
		String user = "Target: " + target + "\nObjective: " + describedObjective + "\nAvailable discoverers: "
				+ availableDiscoverers;
		try {
			ScanPlan plan = this.chatClient.prompt()
				.system(SYSTEM)
				.user(user)
				.tools(reconTool)
				.call()
				.entity(ScanPlan.class);
			return sanitise(plan, availableDiscoverers);
		}
		catch (RuntimeException ex) {
			log.warn("LLM planning for {} failed ({}); using a default plan", target, ex.getMessage());
			return fallback(availableDiscoverers);
		}
	}

	private ScanPlan sanitise(ScanPlan plan, List<String> availableDiscoverers) {
		if (plan == null) {
			return fallback(availableDiscoverers);
		}
		String discoverer = plan.recommendedDiscoverer();
		if (!availableDiscoverers.isEmpty() && !availableDiscoverers.contains(discoverer)) {
			log.info("Planner suggested unknown discoverer '{}'; falling back to '{}'", discoverer,
					availableDiscoverers.get(0));
			discoverer = availableDiscoverers.get(0);
		}
		int concurrency = (plan.concurrency() != null && plan.concurrency() > 0) ? plan.concurrency() : 10;
		boolean includePassed = plan.includePassed() != null && plan.includePassed();
		List<String> families = (plan.prioritizedFamilies() != null) ? plan.prioritizedFamilies() : List.of();
		return new ScanPlan(discoverer, families, concurrency, includePassed, plan.rationale());
	}

	private ScanPlan fallback(List<String> availableDiscoverers) {
		String discoverer = availableDiscoverers.isEmpty() ? "blackbox" : availableDiscoverers.get(0);
		return new ScanPlan(discoverer, List.of("INJECTION", "XSS", "AUTHENTICATION", "CONFIGURATION", "LOGIC", "MISC"),
				10, false, "Fallback plan (LLM planning unavailable).");
	}

}

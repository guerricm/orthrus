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

package ch.nexsol.orthrusdast.web;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import ch.nexsol.orthrusdast.web.ai.AiOrchestratorClient;

/**
 * UI entry point for AI-orchestrated campaigns. It only exists when an orchestrator URL
 * is configured, so the base product keeps a UI free of the optional AI add-on. On
 * success it hands off to the existing scan-monitoring pages, reusing all the job
 * progress UI.
 */
@Controller
@ConditionalOnProperty(prefix = "orthrus.ai.orchestrator", name = "url")
public class AiCampaignController {

	private static final Logger log = LoggerFactory.getLogger(AiCampaignController.class);

	private final AiOrchestratorClient orchestratorClient;

	public AiCampaignController(AiOrchestratorClient orchestratorClient) {
		this.orchestratorClient = orchestratorClient;
	}

	@GetMapping("/ai/campaign")
	public String campaignForm() {
		return "ai/campaign";
	}

	@PostMapping("/ai/campaign")
	public Mono<String> launchCampaign(ServerWebExchange exchange, Model model) {
		// WebFlux does not bind form-urlencoded body fields via @RequestParam (that reads
		// query
		// params only), so the form data is read from the exchange like the other web
		// forms do.
		return exchange.getFormData().flatMap((form) -> {
			String target = form.getFirst("target");
			String objective = form.getFirst("objective");
			if (target == null || target.isBlank()) {
				model.addAttribute("error", "A target is required.");
				return Mono.just("ai/campaign");
			}
			return this.orchestratorClient.launchCampaign(target.trim(), objective).map((result) -> {
				if (result.jobId() == null) {
					model.addAttribute("error", "The orchestrator could not launch a scan on the manager.");
					model.addAttribute("plan", result.plan());
					return "ai/campaign";
				}
				log.info("AI campaign launched job {} on {}", result.jobId(), result.target());
				return "redirect:/scans/all";
			}).onErrorResume((e) -> {
				log.error("AI campaign for {} failed: {}", target, e.getMessage());
				model.addAttribute("error", "AI orchestrator error: " + e.getMessage());
				return Mono.just("ai/campaign");
			});
		});
	}

}

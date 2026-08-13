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

package ch.nexsol.orthrusai.scanner.ai;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import tools.jackson.databind.ObjectMapper;

import ch.nexsol.orthrusai.scanner.ai.tool.FindingTool;
import ch.nexsol.orthrusai.scanner.ai.tool.HttpProbeTool;
import ch.nexsol.orthrusai.scanner.config.AiScannerProperties;
import ch.nexsol.orthrusai.scanner.recon.DiscoveredEndpoint;
import ch.nexsol.orthrusai.scanner.wire.Vulnerability;

/**
 * Runs one family agent against one endpoint. It builds fresh, run-scoped tools (so
 * budgets and findings never leak between endpoints), drives the LLM tool-calling loop
 * synchronously, and returns whatever the agent proved through the finding tool. The
 * blocking call is intentional and confined to the bounded-elastic thread the executor
 * schedules it on.
 */
@Component
@ConditionalOnProperty(prefix = "orthrus.ai", name = "enabled", havingValue = "true")
public class FamilyAgent {

	private static final Logger log = LoggerFactory.getLogger(FamilyAgent.class);

	private final ChatClient chatClient;

	private final WebClient probeWebClient;

	private final ScopeGuard scopeGuard;

	private final ObjectMapper objectMapper;

	private final int maxHttpCallsPerOperation;

	public FamilyAgent(ChatClient scannerChatClient, WebClient.Builder webClientBuilder, ScopeGuard scopeGuard,
			ObjectMapper objectMapper, AiScannerProperties properties) {
		this.chatClient = scannerChatClient;
		this.probeWebClient = webClientBuilder.build();
		this.scopeGuard = scopeGuard;
		this.objectMapper = objectMapper;
		this.maxHttpCallsPerOperation = properties.getAi().getBudget().getMaxHttpCallsPerOperation();
	}

	/**
	 * Probes one endpoint for one family and returns the findings the agent confirmed.
	 * @param family the scanner family name
	 * @param endpoint the endpoint to probe
	 * @return the confirmed findings (possibly empty)
	 */
	public List<Vulnerability> scan(String family, DiscoveredEndpoint endpoint) {
		String scannerId = "ai-" + family.toLowerCase();
		RunContext runContext = new RunContext(endpoint.url(), scannerId, this.maxHttpCallsPerOperation);
		HttpProbeTool httpProbeTool = new HttpProbeTool(this.probeWebClient, this.scopeGuard, this.objectMapper,
				runContext);
		FindingTool findingTool = new FindingTool(runContext, endpoint.url(), endpoint.method());

		String userPrompt = "Test this endpoint: " + endpoint.method() + " " + endpoint.url();
		try {
			this.chatClient.prompt()
				.system(FamilyPrompts.forFamily(family))
				.user(userPrompt)
				.tools(httpProbeTool, findingTool)
				.call()
				.content();
		}
		catch (RuntimeException ex) {
			log.warn("Family agent {} failed on {} {}: {}", family, endpoint.method(), endpoint.url(), ex.getMessage());
		}
		log.debug("Family {} on {} {} used {} HTTP call(s), {} finding(s)", family, endpoint.method(), endpoint.url(),
				runContext.httpCallsUsed(), runContext.findings().size());
		return runContext.findings();
	}

}

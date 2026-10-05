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

import java.time.Duration;
import java.util.List;

import javax.net.ssl.SSLException;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;
import tools.jackson.databind.ObjectMapper;

import ch.nexsol.orthrus.protocol.ai.Endpoint;
import ch.nexsol.orthrus.protocol.node.Vulnerability;
import ch.nexsol.orthrusai.scanner.ai.tool.FindingTool;
import ch.nexsol.orthrusai.scanner.ai.tool.HttpProbeTool;
import ch.nexsol.orthrusai.scanner.config.AiScannerProperties;

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

	private volatile WebClient insecureWebClient;

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
	 * @param context the orchestrator's shared target fingerprint, given to the agent as
	 * prior knowledge (may be null or blank)
	 * @param probeConfig the credentials, TLS leniency and timeout to apply to every
	 * probe
	 * @return the confirmed findings (possibly empty)
	 */
	public List<Vulnerability> scan(String family, Endpoint endpoint, String context, ProbeConfig probeConfig) {
		String scannerId = "ai-" + family.toLowerCase();
		RunContext runContext = new RunContext(endpoint.url(), scannerId, this.maxHttpCallsPerOperation);
		WebClient probeClient = probeConfig.ignoreSslErrors() ? insecureWebClient() : this.probeWebClient;
		HttpProbeTool httpProbeTool = new HttpProbeTool(probeClient, this.scopeGuard, this.objectMapper, runContext,
				probeConfig.credentials(), Duration.ofMillis(probeConfig.readTimeoutMs()));
		FindingTool findingTool = new FindingTool(runContext, endpoint.url(), endpoint.method());

		String userPrompt = "Test this endpoint: " + endpoint.method() + " " + endpoint.url();
		if (context != null && !context.isBlank()) {
			userPrompt += "\n\nPrior recon of the target (shared context): " + context;
		}
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
		log.info("Family {} on {} {} used {} HTTP call(s), {} finding(s)", family, endpoint.method(), endpoint.url(),
				runContext.httpCallsUsed(), runContext.findings().size());
		return runContext.findings();
	}

	/**
	 * A probe client that trusts any certificate, built once on demand. Used only when
	 * the operator opted into ignoring SSL errors for the target (e.g. self-signed
	 * staging).
	 * @return the insecure web client
	 */
	private WebClient insecureWebClient() {
		WebClient client = this.insecureWebClient;
		if (client == null) {
			synchronized (this) {
				client = this.insecureWebClient;
				if (client == null) {
					try {
						SslContext sslContext = SslContextBuilder.forClient()
							.trustManager(InsecureTrustManagerFactory.INSTANCE)
							.build();
						HttpClient httpClient = HttpClient.create().secure((sslSpec) -> sslSpec.sslContext(sslContext));
						client = WebClient.builder()
							.clientConnector(new ReactorClientHttpConnector(httpClient))
							.build();
					}
					catch (SSLException ex) {
						log.warn("Could not build an SSL-lenient client ({}); using the default probe client",
								ex.getMessage());
						client = this.probeWebClient;
					}
					this.insecureWebClient = client;
				}
			}
		}
		return client;
	}

}

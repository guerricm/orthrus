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

package ch.nexsol.orthrusai.orchestrator.ai;

import java.time.Duration;

import org.springframework.ai.tool.annotation.Tool;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

/**
 * A read-only fingerprint of the campaign target, used by the planner to choose a
 * discoverer and prioritise families. It only ever touches the fixed target, so it cannot
 * be steered elsewhere.
 */
public class TargetReconTool {

	private final WebClient webClient;

	private final String target;

	public TargetReconTool(WebClient webClient, String target) {
		this.webClient = webClient;
		this.target = target;
	}

	@Tool(description = "Fingerprint the target: fetch it once and return the status and the "
			+ "technology-revealing response headers (Server, X-Powered-By, Content-Type, etc.).")
	public String fingerprint() {
		try {
			return this.webClient.get()
				.uri(this.target)
				.exchangeToMono(this::describe)
				.timeout(Duration.ofSeconds(10))
				.block(Duration.ofSeconds(12));
		}
		catch (RuntimeException ex) {
			return "Target could not be fingerprinted: " + ex.getMessage();
		}
	}

	private Mono<String> describe(ClientResponse response) {
		StringBuilder sb = new StringBuilder();
		sb.append("Target: ").append(this.target).append('\n');
		sb.append("HTTP ").append(response.statusCode().value()).append('\n');
		response.headers()
			.asHttpHeaders()
			.forEach((name, values) -> sb.append(name).append(": ").append(String.join(",", values)).append('\n'));
		return response.releaseBody().thenReturn(sb.toString());
	}

}

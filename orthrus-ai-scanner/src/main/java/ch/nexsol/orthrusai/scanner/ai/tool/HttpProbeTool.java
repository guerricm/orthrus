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

package ch.nexsol.orthrusai.scanner.ai.tool;

import java.time.Duration;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;
import org.springframework.http.HttpMethod;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

import ch.nexsol.orthrusai.scanner.ai.RunContext;
import ch.nexsol.orthrusai.scanner.ai.ScopeGuard;

/**
 * The agent's only way to touch the network. It forges the request the model asks for,
 * but only against the in-scope target and only while the HTTP budget lasts, then returns
 * a compact, token-friendly view of the response for the model to reason about. Bridging
 * the reactive client with a blocking call is safe here: the whole agent runs on a
 * bounded-elastic thread.
 */
public class HttpProbeTool {

	private static final Logger log = LoggerFactory.getLogger(HttpProbeTool.class);

	private static final int MAX_BODY_CHARS = 4000;

	private final WebClient webClient;

	private final ScopeGuard scopeGuard;

	private final ObjectMapper objectMapper;

	private final RunContext runContext;

	public HttpProbeTool(WebClient webClient, ScopeGuard scopeGuard, ObjectMapper objectMapper, RunContext runContext) {
		this.webClient = webClient;
		this.scopeGuard = scopeGuard;
		this.objectMapper = objectMapper;
		this.runContext = runContext;
	}

	@Tool(description = "Send an HTTP request to the target under test and return the response "
			+ "(status line, headers, and truncated body). Only the target host is reachable.")
	public String sendRequest(
			@ToolParam(description = "Absolute URL to request (must be on the target host)") String url,
			@ToolParam(description = "HTTP method, e.g. GET, POST, PUT, DELETE, PATCH") String method,
			@ToolParam(required = false,
					description = "JSON object of extra request headers, or empty") String headersJson,
			@ToolParam(required = false, description = "Request body to send, or empty") String body) {

		if (!this.scopeGuard.inScope(url, this.runContext.targetUrl())) {
			return "REFUSED: '" + url + "' is out of scope. Only the target host " + this.runContext.targetUrl()
					+ " may be probed.";
		}
		if (!this.runContext.tryConsumeHttpCall()) {
			return "BUDGET_EXCEEDED: the HTTP request budget for this endpoint is spent. "
					+ "Report your findings and stop.";
		}

		HttpMethod httpMethod = HttpMethod.valueOf((method != null) ? method.trim().toUpperCase() : "GET");
		try {
			WebClient.RequestBodySpec spec = this.webClient.method(httpMethod).uri(url);
			applyHeaders(spec, headersJson);
			if (body != null && !body.isBlank()) {
				spec.bodyValue(body);
			}
			return spec.exchangeToMono(this::render).timeout(Duration.ofSeconds(15)).block(Duration.ofSeconds(20));
		}
		catch (RuntimeException ex) {
			log.debug("Probe {} {} failed: {}", httpMethod, url, ex.getMessage());
			return "ERROR: request failed: " + ex.getMessage();
		}
	}

	private void applyHeaders(WebClient.RequestBodySpec spec, String headersJson) {
		if (headersJson == null || headersJson.isBlank()) {
			return;
		}
		try {
			Map<String, String> headers = this.objectMapper.readValue(headersJson,
					new TypeReference<Map<String, String>>() {
					});
			headers.forEach((key, value) -> {
				if (key != null && value != null) {
					spec.header(key, value.replaceAll("[\\r\\n]", ""));
				}
			});
		}
		catch (RuntimeException ex) {
			log.debug("Ignoring unparseable headers JSON: {}", ex.getMessage());
		}
	}

	private Mono<String> render(ClientResponse response) {
		return response.bodyToMono(String.class).defaultIfEmpty("").map((responseBody) -> {
			StringBuilder sb = new StringBuilder();
			sb.append("HTTP ").append(response.statusCode().value()).append('\n');
			response.headers()
				.asHttpHeaders()
				.forEach((name, values) -> sb.append(name).append(": ").append(String.join(",", values)).append('\n'));
			sb.append('\n');
			sb.append((responseBody.length() > MAX_BODY_CHARS)
					? responseBody.substring(0, MAX_BODY_CHARS) + "...[truncated]" : responseBody);
			return sb.toString();
		});
	}

}

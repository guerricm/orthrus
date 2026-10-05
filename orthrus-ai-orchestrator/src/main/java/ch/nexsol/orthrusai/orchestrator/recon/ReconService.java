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

package ch.nexsol.orthrusai.orchestrator.recon;

import java.time.Duration;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import tools.jackson.databind.ObjectMapper;

import ch.nexsol.orthrus.protocol.ai.Credential;
import ch.nexsol.orthrus.protocol.ai.Credentials;
import ch.nexsol.orthrus.protocol.ai.Endpoint;
import ch.nexsol.orthrus.protocol.ai.OpenApiEndpoints;
import ch.nexsol.orthrus.protocol.ai.ReconResult;

/**
 * The orchestrator's recon: fingerprint the target once and map its endpoints. If the
 * target serves an OpenAPI document, its paths and methods become the endpoint list,
 * resolved against the document's {@code servers} base path; otherwise the target URL
 * itself is the single endpoint. Kept deterministic so it works without a model; the LLM
 * planner reuses the same picture.
 */
@Service
public class ReconService {

	private static final Logger log = LoggerFactory.getLogger(ReconService.class);

	private final WebClient webClient;

	private final ObjectMapper objectMapper;

	public ReconService(WebClient.Builder webClientBuilder, ObjectMapper objectMapper) {
		this.webClient = webClientBuilder.build();
		this.objectMapper = objectMapper;
	}

	/**
	 * Fingerprints the target and discovers its endpoints.
	 * @param target the target URL (an app root or an OpenAPI document)
	 * @return the recon result, never empty (falls back to the target itself)
	 */
	public Mono<ReconResult> discover(String target) {
		return discover(target, null, List.of());
	}

	/**
	 * Fingerprints the target and discovers its endpoints, sending the given credentials
	 * so a protected OpenAPI document can be read, and forcing the base host when the
	 * caller overrides it.
	 * @param target the target URL (an app root or an OpenAPI document)
	 * @param overrideHost the base host to force on discovered endpoints, or null
	 * @param credentials credentials to send while fetching the document
	 * @return the recon result, never empty (falls back to the target itself)
	 */
	public Mono<ReconResult> discover(String target, String overrideHost, List<Credential> credentials) {
		WebClient.RequestHeadersSpec<?> request = this.webClient.get()
			.uri(Credentials.withQueryCredentials(target, credentials));
		Credentials.applyHeaderAndCookie(request, credentials);
		return request
			.exchangeToMono((response) -> response.bodyToMono(String.class)
				.defaultIfEmpty("")
				.map((body) -> build(target, overrideHost, response, body)))
			.timeout(Duration.ofSeconds(10))
			.onErrorResume((e) -> {
				log.debug("Recon of {} failed ({}); using target as single endpoint", target, e.getMessage());
				return Mono.just(new ReconResult(OpenApiEndpoints.origin(target), List.of(new Endpoint("GET", target)),
						"Target could not be fingerprinted: " + e.getMessage()));
			});
	}

	private ReconResult build(String target, String overrideHost, ClientResponse response, String body) {
		OpenApiEndpoints parsed = OpenApiEndpoints.parse(this.objectMapper, target, body);
		List<Endpoint> endpoints = parsed.endpoints().isEmpty() ? List.of(new Endpoint("GET", target))
				: parsed.endpoints();
		String base = parsed.baseUrl();
		if (overrideHost != null && !overrideHost.isBlank()) {
			base = OpenApiEndpoints.rewriteHost(base, overrideHost);
			endpoints = endpoints.stream()
				.map((e) -> new Endpoint(e.method(), OpenApiEndpoints.rewriteHost(e.url(), overrideHost)))
				.toList();
		}
		log.info("Recon of {} found {} endpoint(s)", target, endpoints.size());
		return new ReconResult(base, endpoints, fingerprint(target, response, endpoints.size()));
	}

	private String fingerprint(String target, ClientResponse response, int endpointCount) {
		HttpHeaders headers = response.headers().asHttpHeaders();
		StringBuilder sb = new StringBuilder();
		sb.append("Target ")
			.append(target)
			.append(" responded HTTP ")
			.append(response.statusCode().value())
			.append(". ");
		appendHeader(sb, headers, "Server");
		appendHeader(sb, headers, "X-Powered-By");
		appendHeader(sb, headers, "Content-Type");
		sb.append(endpointCount).append(" endpoint(s) discovered.");
		return sb.toString();
	}

	private void appendHeader(StringBuilder sb, HttpHeaders headers, String name) {
		String value = headers.getFirst(name);
		if (value != null && !value.isBlank()) {
			sb.append(name).append("=").append(value).append("; ");
		}
	}

}

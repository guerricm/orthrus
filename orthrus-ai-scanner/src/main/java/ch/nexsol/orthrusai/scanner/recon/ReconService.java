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

package ch.nexsol.orthrusai.scanner.recon;

import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * Minimal self-recon for the AI node. If the target serves an OpenAPI document, its paths
 * and methods become the endpoint list; otherwise the target URL itself is the single
 * endpoint. The LLM agents then probe each endpoint. Kept deliberately small: deep
 * crawling can be layered on later.
 */
@Service
public class ReconService {

	private static final Logger log = LoggerFactory.getLogger(ReconService.class);

	private static final int MAX_ENDPOINTS = 50;

	private static final List<String> HTTP_METHODS = List.of("get", "put", "post", "delete", "patch");

	private final WebClient webClient;

	private final ObjectMapper objectMapper;

	public ReconService(WebClient.Builder webClientBuilder, ObjectMapper objectMapper) {
		this.webClient = webClientBuilder.build();
		this.objectMapper = objectMapper;
	}

	/**
	 * Discovers the endpoints to scan on the target.
	 * @param target the target URL (an app root or an OpenAPI document)
	 * @return the endpoints found, never empty (falls back to the target itself)
	 */
	public Mono<List<DiscoveredEndpoint>> discover(String target) {
		return this.webClient.get()
			.uri(target)
			.retrieve()
			.bodyToMono(String.class)
			.timeout(Duration.ofSeconds(10))
			.map((body) -> parseOpenApi(target, body))
			.onErrorResume((e) -> {
				log.debug("Recon fetch of {} failed ({}); using target as single endpoint", target, e.getMessage());
				return Mono.just(List.<DiscoveredEndpoint>of());
			})
			.map((endpoints) -> endpoints.isEmpty() ? List.of(new DiscoveredEndpoint(target, "GET")) : endpoints);
	}

	private List<DiscoveredEndpoint> parseOpenApi(String target, String body) {
		if (body == null || body.isBlank()) {
			return List.of();
		}
		try {
			JsonNode root = this.objectMapper.readTree(body);
			JsonNode paths = root.get("paths");
			boolean looksOpenApi = root.has("openapi") || root.has("swagger");
			if (!looksOpenApi || paths == null || !paths.isObject()) {
				return List.of();
			}
			String base = origin(target);
			List<DiscoveredEndpoint> endpoints = new ArrayList<>();
			paths.properties().forEach((entry) -> {
				String path = entry.getKey();
				JsonNode methods = entry.getValue();
				for (String method : HTTP_METHODS) {
					if (methods.has(method) && endpoints.size() < MAX_ENDPOINTS) {
						endpoints.add(new DiscoveredEndpoint(base + path, method.toUpperCase(Locale.ROOT)));
					}
				}
			});
			log.info("Recon parsed {} endpoint(s) from OpenAPI at {}", endpoints.size(), target);
			return endpoints;
		}
		catch (RuntimeException ex) {
			return List.of();
		}
	}

	private String origin(String target) {
		try {
			URI uri = URI.create(target);
			String scheme = (uri.getScheme() != null) ? uri.getScheme() : "http";
			int port = uri.getPort();
			String authority = (port != -1) ? uri.getHost() + ":" + port : uri.getHost();
			return scheme + "://" + authority;
		}
		catch (IllegalArgumentException ex) {
			return target;
		}
	}

}

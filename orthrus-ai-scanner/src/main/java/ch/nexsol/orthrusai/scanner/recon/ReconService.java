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

import java.time.Duration;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import tools.jackson.databind.ObjectMapper;

import ch.nexsol.orthrus.protocol.ai.Endpoint;
import ch.nexsol.orthrus.protocol.ai.OpenApiEndpoints;

/**
 * Minimal self-recon for the AI node, used when a task carries no shared recon from the
 * orchestrator. If the target serves an OpenAPI document, its paths and methods become
 * the endpoint list; otherwise the target URL itself is the single endpoint.
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
	 * Discovers the endpoints to scan on the target.
	 * @param target the target URL (an app root or an OpenAPI document)
	 * @return the endpoints found, never empty (falls back to the target itself)
	 */
	public Mono<List<Endpoint>> discover(String target) {
		return this.webClient.get()
			.uri(target)
			.retrieve()
			.bodyToMono(String.class)
			.timeout(Duration.ofSeconds(10))
			.map((body) -> OpenApiEndpoints.parse(this.objectMapper, target, body).endpoints())
			.doOnNext(
					(endpoints) -> log.info("Recon parsed {} endpoint(s) from OpenAPI at {}", endpoints.size(), target))
			.onErrorResume((e) -> {
				log.debug("Recon fetch of {} failed ({}); using target as single endpoint", target, e.getMessage());
				return Mono.just(List.<Endpoint>of());
			})
			.map((endpoints) -> endpoints.isEmpty() ? List.of(new Endpoint("GET", target)) : endpoints);
	}

}

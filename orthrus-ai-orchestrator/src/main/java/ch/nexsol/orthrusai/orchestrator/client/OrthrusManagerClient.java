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

package ch.nexsol.orthrusai.orchestrator.client;

import java.time.Duration;
import java.util.List;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import ch.nexsol.orthrusai.orchestrator.config.AiOrchestratorProperties;
import ch.nexsol.orthrusai.orchestrator.wire.ScanJobAccepted;
import ch.nexsol.orthrusai.orchestrator.wire.ScanRequest;

/**
 * Drives the orthrus manager's public API. The orchestrator never touches the manager's
 * internals; it launches scans and reads the fleet's discoverers exactly as an external
 * API client would.
 */
@Component
public class OrthrusManagerClient {

	private final WebClient webClient;

	private final String managerUrl;

	public OrthrusManagerClient(AiOrchestratorProperties properties, WebClient.Builder webClientBuilder) {
		this.managerUrl = properties.getManager().getUrl();
		String username = properties.getManager().getUsername();
		// The manager secures its public API; authenticate with HTTP Basic when
		// credentials are set.
		if (username != null && !username.isBlank()) {
			webClientBuilder
				.defaultHeaders((headers) -> headers.setBasicAuth(username, properties.getManager().getPassword()));
		}
		this.webClient = webClientBuilder.build();
	}

	/**
	 * Lists the discoverers available across the manager's fleet.
	 * @return the discoverer ids
	 */
	public Mono<List<String>> getDiscoverers() {
		return this.webClient.get()
			.uri(this.managerUrl + "/api/v1/scans/discoverers")
			.retrieve()
			.bodyToMono(new ParameterizedTypeReference<List<String>>() {
			})
			.timeout(Duration.ofSeconds(10));
	}

	/**
	 * Launches a scan on the manager.
	 * @param request the scan request
	 * @return the accepted job
	 */
	public Mono<ScanJobAccepted> launchScan(ScanRequest request) {
		return this.webClient.post()
			.uri(this.managerUrl + "/api/v1/scans")
			.bodyValue(request)
			.retrieve()
			.bodyToMono(ScanJobAccepted.class)
			.timeout(Duration.ofSeconds(15));
	}

}

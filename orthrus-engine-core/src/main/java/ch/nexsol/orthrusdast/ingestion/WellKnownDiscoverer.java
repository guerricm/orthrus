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

package ch.nexsol.orthrusdast.ingestion;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import ch.nexsol.orthrusdast.http.ScanHttpClient;
import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.SecurityScheme;

/**
 * Discovers endpoints by checking standard well-known paths.
 */
@Component
public class WellKnownDiscoverer implements EndpointDiscoverer {

	private static final Logger log = LoggerFactory.getLogger(WellKnownDiscoverer.class);

	private final ScanHttpClient httpClient;

	private static final String[] WELL_KNOWN_PATHS = { "/.well-known/openid-configuration", "/.well-known/jwks.json",
			"/.well-known/security.txt", "/swagger-ui.html", "/swagger-ui/index.html", "/v3/api-docs", "/api-docs",
			"/openapi.json", "/.env", "/.env.dev", "/.git/config", "/actuator", "/actuator/env", "/health" };

	public WellKnownDiscoverer(ScanHttpClient httpClient) {
		this.httpClient = httpClient;
	}

	@Override
	public String getId() {
		return "well-known";
	}

	@Override
	public Mono<List<Operation>> discover(String targetUrl, ch.nexsol.orthrusdast.model.ScanConfiguration config) {
		ch.nexsol.orthrusdast.model.SecurityScheme authScheme = config != null ? config.authScheme() : null;
		log.info("Starting well-known path discovery for base URL: {}", targetUrl);

		String baseUrl = targetUrl.endsWith("/") ? targetUrl.substring(0, targetUrl.length() - 1) : targetUrl;

		return Flux.fromArray(WELL_KNOWN_PATHS).flatMap((path) -> checkPath(baseUrl + path, authScheme)).collectList();
	}

	private Mono<Operation> checkPath(String url, SecurityScheme authScheme) {
		Operation op = Operation.simple(url, org.springframework.http.HttpMethod.GET).withAuth(authScheme);
		return httpClient.send(op).flatMap((response) -> {
			// Only consider it "discovered" if it returns a 200 OK
			if (response.isSuccessful()) {
				log.debug("Discovered well-known path: {}", url);
				return Mono.just(op);
			}
			return Mono.empty();
		});
	}

}

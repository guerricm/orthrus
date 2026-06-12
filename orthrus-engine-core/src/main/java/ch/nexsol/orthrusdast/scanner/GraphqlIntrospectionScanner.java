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

package ch.nexsol.orthrusdast.scanner;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import reactor.core.publisher.Flux;

import ch.nexsol.orthrusdast.http.ScanHttpClient;
import ch.nexsol.orthrusdast.model.CWEReference;
import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.RiskLevel;
import ch.nexsol.orthrusdast.model.Vulnerability;

import org.springframework.http.HttpMethod;

/**
 * Scans for GraphQL Introspection enabled in production (Information Disclosure).
 */
@Component
public class GraphqlIntrospectionScanner implements SecurityScanner {

	private static final Logger log = LoggerFactory.getLogger(GraphqlIntrospectionScanner.class);

	private final ScanHttpClient httpClient;

	private static final String INTROSPECTION_QUERY = "{\"query\": \"query { __schema { queryType { name } } }\"}";

	private static final String FIELD_SUGGESTION_QUERY = "{\"query\": \"query { __schem }\"}"; // Intentional
																								// typo

	public GraphqlIntrospectionScanner(ScanHttpClient httpClient) {
		this.httpClient = httpClient;
	}

	@Override
	public String getId() {
		return "graphql-introspection";
	}

	@Override
	public String getName() {
		return "GraphQL Introspection Scanner";
	}

	@Override
	public ScannerFamily getFamily() {
		return ScannerFamily.LOGIC;
	}

	@Override
	public Flux<Vulnerability> scan(Operation operation) {
		return Flux.defer(() -> {
			// Very basic heuristic: if it looks like a GraphQL operation
			if (operation.body() != null && !operation.body().contains("\"query\"")
					&& !operation.url().contains("graphql")) {
				return Flux.empty();
			}

			log.debug("Scanning for GraphQL Introspection: {}", operation.url());

			Operation testOpPost = new Operation(operation.url(), HttpMethod.POST,
					Map.of("Content-Type", "application/json"), Collections.emptyMap(), INTROSPECTION_QUERY,
					operation.securityRequirements(), operation.expectedContentTypes(), operation.authScheme());

			Operation testOpGet = new Operation(operation.url(), HttpMethod.GET, Collections.emptyMap(),
					Map.of("query", "query { __schema { queryType { name } } }"), null,
					operation.securityRequirements(), operation.expectedContentTypes(), operation.authScheme());

			Operation testOpFieldSuggestion = new Operation(operation.url(), HttpMethod.POST,
					Map.of("Content-Type", "application/json"), Collections.emptyMap(), FIELD_SUGGESTION_QUERY,
					operation.securityRequirements(), operation.expectedContentTypes(), operation.authScheme());

			Flux<Vulnerability> postVuln = httpClient.send(testOpPost).flatMapMany((response) -> {
				if (response.statusCode().is2xxSuccessful() && response.bodyContains("__schema")
						&& response.bodyContains("queryType")) {
					return Flux.just(createVulnerabilityWithTrace("GraphQL Introspection Enabled (POST)",
							"The GraphQL endpoint has introspection enabled, exposing the entire API schema via POST.",
							RiskLevel.LOW, Vulnerability.Confidence.HIGH, operation, CWEReference.CWE_200,
							List.of("CAPEC-118"), 4.3,
							"The server responded with the schema details to an introspection query.",
							"Disable GraphQL introspection in production environments.", testOpPost, response,
							"API Endpoint (Network)", "Unauthorized Access / Data Exposure"));
				}
				return Flux.empty();
			});

			Flux<Vulnerability> getVuln = httpClient.send(testOpGet).flatMapMany((response) -> {
				if (response.statusCode().is2xxSuccessful() && response.bodyContains("__schema")
						&& response.bodyContains("queryType")) {
					return Flux.just(createVulnerabilityWithTrace("GraphQL Introspection Enabled (GET)",
							"The GraphQL endpoint has introspection enabled and accepts GET requests, exposing the entire API schema and potentially allowing CSRF.",
							RiskLevel.MEDIUM, Vulnerability.Confidence.HIGH, operation, CWEReference.CWE_200,
							List.of("CAPEC-118"), 5.3,
							"The server responded with the schema details to an introspection query over GET.",
							"Disable GraphQL introspection in production environments. Disable GraphQL over GET for state-changing operations.",
							testOpGet, response, "API Endpoint (Network)", "Unauthorized Access / Data Exposure"));
				}
				return Flux.empty();
			});

			Flux<Vulnerability> suggestionVuln = httpClient.send(testOpFieldSuggestion).flatMapMany((response) -> {
				if (response.bodyContains("Did you mean") && response.bodyContains("__schema")) {
					return Flux.just(createVulnerabilityWithTrace("GraphQL Field Suggestion Enabled",
							"The GraphQL endpoint returns 'Did you mean ...' suggestions for invalid fields. This allows attackers to fuzz and map the schema even if introspection is disabled.",
							RiskLevel.LOW, Vulnerability.Confidence.HIGH, operation, CWEReference.CWE_200,
							List.of("CAPEC-118"), 3.7, "The server suggested '__schema' when queried with '__schem'.",
							"Disable field suggestions (e.g. Apollo Server's validation rules) in production.",
							testOpFieldSuggestion, response, "API Endpoint (Network)",
							"Unauthorized Access / Data Exposure"));
				}
				return Flux.empty();
			});

			return Flux.concat(postVuln, getVuln, suggestionVuln);
		});
	}

	private String truncate(String text) {
		if (text == null) {
			return "null";
		}
		return (text.length() > 200) ? text.substring(0, 200) + "..." : text;
	}

}

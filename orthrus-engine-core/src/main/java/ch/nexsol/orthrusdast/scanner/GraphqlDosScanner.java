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

import java.util.List;

import org.springframework.stereotype.Component;

import reactor.core.publisher.Flux;

import ch.nexsol.orthrusdast.http.ScanHttpClient;
import ch.nexsol.orthrusdast.model.CWEReference;
import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.RiskLevel;
import ch.nexsol.orthrusdast.model.Vulnerability;

/**
 * Scans for GraphQL Denial of Service via deeply nested queries (CWE-400/CWE-770).
 */
@Component
public class GraphqlDosScanner implements SecurityScanner {

	private final ScanHttpClient httpClient;

	// Deeply nested introspection query (often works without knowing the schema)
	private static final String INTROSPECTION_DOS = "{\"query\":\"query { __schema { types { fields { type { fields { type { fields { type { fields { name } } } } } } } } } }\"}";

	// Alias batching payload (1000 aliases)
	private static final String ALIAS_DOS;
	static {
		StringBuilder sb = new StringBuilder("{\"query\":\"query { ");
		for (int i = 0; i < 1000; i++) {
			sb.append("a").append(i).append(":__typename ");
		}
		sb.append("}\"}");
		ALIAS_DOS = sb.toString();
	}

	public GraphqlDosScanner(ScanHttpClient httpClient) {
		this.httpClient = httpClient;
	}

	@Override
	public String getId() {
		return "graphql-dos";
	}

	@Override
	public String getName() {
		return "GraphQL DoS Scanner";
	}

	@Override
	public Flux<Vulnerability> scan(Operation operation) {
		return Flux.defer(() -> {
			// Only target GraphQL endpoints
			if (!operation.url().toLowerCase().contains("graphql") && !(operation.expectedContentTypes() != null
					&& operation.expectedContentTypes().contains("application/graphql"))) {
				return Flux.empty();
			}

			if (!"POST".equals(operation.method().toUpperCase())) {
				return Flux.empty();
			}

			java.util.Map<String, String> newHeaders = new java.util.HashMap<>(operation.headers());
			newHeaders.put("Content-Type", "application/json");

			Operation testOpIntrospection = new Operation(operation.url(), operation.method(), newHeaders,
					operation.queryParams(), INTROSPECTION_DOS, operation.securityRequirements(),
					operation.expectedContentTypes(), operation.authScheme());

			Operation testOpAlias = new Operation(operation.url(), operation.method(), newHeaders,
					operation.queryParams(), ALIAS_DOS, operation.securityRequirements(),
					operation.expectedContentTypes(), operation.authScheme());

			return Flux.concat(executeDosCheck(testOpIntrospection, operation, "Deep Introspection Query"),
					executeDosCheck(testOpAlias, operation, "Alias Batching (1000 aliases)"));
		});
	}

	private Flux<Vulnerability> executeDosCheck(Operation testOp, Operation originalOp, String payloadType) {
		long startTime = System.currentTimeMillis();
		return httpClient.send(testOp).flatMapMany((response) -> {
			long duration = System.currentTimeMillis() - startTime;

			// If the server takes an unusually long time (> 3000ms) or crashes (5xx)
			if (response.statusCode().is5xxServerError() || duration > 3000) {
				Vulnerability vuln = createVulnerabilityWithTrace("GraphQL Denial of Service - " + payloadType,
						"The GraphQL endpoint allowed an expensive query (" + payloadType
								+ "), causing high response times or a server error. This indicates a lack of query cost analysis or depth limiting.",
						RiskLevel.HIGH, Vulnerability.Confidence.MEDIUM, originalOp, CWEReference.CWE_770,
						List.of("CAPEC-130"), 7.5,
						"Server took " + duration + "ms or returned " + response.statusCode()
								+ " when processing the query.",
						"Implement GraphQL query depth limiting, alias limits, and cost analysis to prevent expensive queries from consuming server resources. Disable Introspection in production.",
						testOp, response, "API Endpoint (Network)", "Unauthorized Access / Data Exposure");
				return Flux.just(vuln);
			}
			return Flux.empty();
		});
	}

}

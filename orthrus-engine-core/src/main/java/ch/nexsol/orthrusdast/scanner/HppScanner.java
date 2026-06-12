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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import ch.nexsol.orthrusdast.http.ScanHttpClient;
import ch.nexsol.orthrusdast.model.CWEReference;
import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.RiskLevel;
import ch.nexsol.orthrusdast.model.Vulnerability;

/**
 * Scans for HTTP Parameter Pollution (HPP) (CWE-235).
 */
@Component
public class HppScanner implements SecurityScanner {

	private static final Logger log = LoggerFactory.getLogger(HppScanner.class);

	private static final String PAYLOAD = "orthrus_hpp_test";

	private final ScanHttpClient httpClient;

	private final ObjectMapper mapper = new ObjectMapper();

	public HppScanner(ScanHttpClient httpClient) {
		this.httpClient = httpClient;
	}

	@Override
	public String getId() {
		return "hpp";
	}

	@Override
	public String getName() {
		return "HTTP Parameter Pollution Scanner";
	}

	@Override
	public ScannerFamily getFamily() {
		return ScannerFamily.LOGIC;
	}

	@Override
	public Flux<Vulnerability> scan(Operation operation) {
		List<Mono<Vulnerability>> checks = new ArrayList<>();

		// 1. Query Parameters HPP
		if (operation.queryParams() != null && !operation.queryParams().isEmpty()) {
			for (String param : operation.queryParams().keySet()) {
				String originalValue = operation.queryParams().get(param);
				if (originalValue == null) {
					originalValue = "";
				}

				// Build the base URL with all parameters except the one we're duplicating
				UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(operation.url());
				for (var entry : operation.queryParams().entrySet()) {
					if (!entry.getKey().equals(param)) {
						builder.queryParam(entry.getKey(), entry.getValue());
					}
				}

				// Append the parameter twice to test pollution
				builder.queryParam(param, originalValue);
				builder.queryParam(param, PAYLOAD);

				String pollutedUrl = builder.build().toUriString();

				// We clear queryParams so ScanHttpClient uses the polluted URL exactly
				Operation testOp = new Operation(pollutedUrl, operation.method(), operation.headers(),
						Collections.emptyMap(), operation.body(), operation.securityRequirements(),
						operation.expectedContentTypes(), operation.authScheme(), operation.templateUrl(),
						operation.sourceNode());

				checks.add(executeAndCheck(testOp, operation, "Query Parameter '" + param + "'"));
			}
		}

		// 2. JSON Body HPP
		if (operation.body() != null && operation.body().trim().startsWith("{")) {
			try {
				JsonNode rootNode = mapper.readTree(operation.body());
				if (rootNode.isObject()) {
					for (String field : rootNode.propertyNames()) {
						// To simulate JSON HPP, we need a raw string since JsonNode
						// doesn't allow duplicate keys
						// We'll replace the first occurrence of the key-value pair with a
						// duplicated version
						String bodyStr = operation.body();
						JsonNode valueNode = rootNode.get(field);
						String valueStr = valueNode.isTextual() ? "\"" + valueNode.asText() + "\""
								: valueNode.toString();

						String searchStr = "\"" + field + "\":\\s*" + valueStr;
						String replacementStr = "\"" + field + "\":" + valueStr + ", \"" + field + "\":\"" + PAYLOAD
								+ "\"";

						// Replace using regex to handle spacing
						String pollutedBody = bodyStr.replaceFirst(
								"\"" + field + "\"\\s*:\\s*" + java.util.regex.Pattern.quote(valueStr), replacementStr);

						if (!pollutedBody.equals(bodyStr)) {
							Operation testOp = new Operation(operation.url(), operation.method(), operation.headers(),
									operation.queryParams(), pollutedBody, operation.securityRequirements(),
									operation.expectedContentTypes(), operation.authScheme(), operation.templateUrl(),
									operation.sourceNode());

							checks.add(executeAndCheck(testOp, operation, "JSON Body Field '" + field + "'"));
						}
					}
				}
			}
			catch (Exception ex) {
				log.debug("Failed to parse or mutate JSON body for HPP in {}", operation.url());
			}
		}

		return Flux.fromIterable(checks).flatMap(mono -> mono).filter(vuln -> vuln != null);
	}

	private Mono<Vulnerability> executeAndCheck(Operation testOp, Operation originalOp, String injectionPoint) {
		return httpClient.send(testOp, false).flatMap(response -> {
			boolean is500 = response.statusCode().value() == 500;
			boolean is2xx = response.statusCode().value() >= 200 && response.statusCode().value() < 300;
			boolean reflectsPayload = response.bodyContainsExact(PAYLOAD);

			if (is500) {
				Vulnerability vuln = createVulnerabilityWithTrace("HTTP Parameter Pollution (HPP) - Server Error",
						"The endpoint crashed (HTTP 500) when duplicate parameters were supplied.", RiskLevel.HIGH,
						Vulnerability.Confidence.HIGH, originalOp, CWEReference.CWE_235, List.of("CAPEC-460"), 7.5,
						"Server returned HTTP 500 when injecting duplicate parameter into " + injectionPoint + ".",
						"Ensure the application handles duplicate parameters safely. Frameworks should expect arrays if multiple values are permitted, or strictly reject duplicate keys.",
						testOp, response, "API Endpoint (Network)", "Denial of Service / Unintended Behavior");
				return Mono.just(vuln);
			}

			if (is2xx && reflectsPayload) {
				Vulnerability vuln = createVulnerabilityWithTrace("HTTP Parameter Pollution (HPP) - Logic Bypass",
						"The endpoint accepted duplicate parameters and prioritized the injected value over the original.",
						RiskLevel.MEDIUM, Vulnerability.Confidence.MEDIUM, originalOp, CWEReference.CWE_235,
						List.of("CAPEC-460"), 5.3,
						"Server processed the request and reflected the injected value ('" + PAYLOAD
								+ "') from the duplicated parameter at " + injectionPoint + ".",
						"Ensure the application handles duplicate parameters safely. Frameworks should expect arrays if multiple values are permitted, or strictly reject duplicate keys.",
						testOp, response, "API Endpoint (Network)", "Unintended Behavior / Logic Bypass");
				return Mono.just(vuln);
			}

			return Mono.empty();
		});
	}

}

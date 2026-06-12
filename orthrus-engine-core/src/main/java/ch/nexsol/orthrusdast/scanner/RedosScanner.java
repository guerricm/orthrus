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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import ch.nexsol.orthrusdast.http.ScanHttpClient;
import ch.nexsol.orthrusdast.model.CWEReference;
import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.RiskLevel;
import ch.nexsol.orthrusdast.model.Vulnerability;

/**
 * Scans for Regular Expression Denial of Service (ReDoS) (CWE-400).
 */
@Component
public class RedosScanner implements SecurityScanner {

	private static final Logger log = LoggerFactory.getLogger(RedosScanner.class);

	private static final List<String> PAYLOADS = List.of("A".repeat(20000) + "B", // Generic
																					// repetitive
																					// payload
																					// to
																					// cause
																					// backtracking
			"(((a.*)+)+)+", // Specific evil regex payload
			"0".repeat(500) + "! " // Number validation ReDoS payload
	);

	private final ScanHttpClient httpClient;

	private final ObjectMapper mapper = new ObjectMapper();

	public RedosScanner(ScanHttpClient httpClient) {
		this.httpClient = httpClient;
	}

	@Override
	public String getId() {
		return "redos";
	}

	@Override
	public String getName() {
		return "ReDoS Scanner";
	}

	@Override
	public ScannerFamily getFamily() {
		return ScannerFamily.LOGIC;
	}

	@Override
	public Flux<Vulnerability> scan(Operation operation) {
		return Flux.defer(() -> {
			// Get a baseline response time
			return httpClient.send(operation, false).flatMapMany(baselineResponse -> {
				long baselineTime = baselineResponse.responseTimeMs();

				List<Mono<Vulnerability>> checks = new ArrayList<>();

				// 1. Query Params ReDoS
				if (operation.queryParams() != null && !operation.queryParams().isEmpty()) {
					for (String param : operation.queryParams().keySet()) {
						for (String payload : PAYLOADS) {
							Map<String, String> newParams = new HashMap<>(operation.queryParams());
							newParams.put(param, payload);

							Operation testOp = new Operation(operation.url(), operation.method(), operation.headers(),
									newParams, operation.body(), operation.securityRequirements(),
									operation.expectedContentTypes(), operation.authScheme(), operation.templateUrl(),
									operation.sourceNode());

							checks.add(executeAndCheck(testOp, operation, "Query Parameter '" + param + "'",
									baselineTime));
						}
					}
				}

				// 2. JSON Body ReDoS
				if (operation.body() != null && operation.body().trim().startsWith("{")) {
					try {
						JsonNode rootNode = mapper.readTree(operation.body());
						if (rootNode.isObject()) {
							List<String> fieldNames = new ArrayList<>();
							rootNode.fieldNames().forEachRemaining(fieldNames::add);
							for (String field : fieldNames) {
								for (String payload : PAYLOADS) {
									ObjectNode clonedNode = ((ObjectNode) rootNode).deepCopy();
									clonedNode.put(field, payload);

									Operation testOp = new Operation(operation.url(), operation.method(),
											operation.headers(), operation.queryParams(),
											mapper.writeValueAsString(clonedNode), operation.securityRequirements(),
											operation.expectedContentTypes(), operation.authScheme(),
											operation.templateUrl(), operation.sourceNode());

									checks.add(executeAndCheck(testOp, operation, "JSON Body Field '" + field + "'",
											baselineTime));
								}
							}
						}
					}
					catch (Exception ex) {
						log.debug("Failed to parse JSON body for ReDoS in {}", operation.url());
					}
				}

				return Flux.fromIterable(checks).flatMap(mono -> mono).filter(vuln -> vuln != null);
			});
		});
	}

	private Mono<Vulnerability> executeAndCheck(Operation testOp, Operation originalOp, String injectionPoint,
			long baselineTime) {
		return httpClient.send(testOp, false).flatMap(response -> {
			long testTime = response.responseTimeMs();

			// Detect if the request took significantly longer than the baseline (Baseline
			// + 8 seconds)
			// Catastrophic backtracking typically causes the thread to lock up for a very
			// long time
			if (testTime > (baselineTime + 8000)) {
				Vulnerability vuln = createVulnerabilityWithTrace("Regular Expression Denial of Service (ReDoS)",
						"The endpoint took an excessively long time to respond (" + testTime + "ms vs baseline "
								+ baselineTime
								+ "ms) when a catastrophic backtracking payload was injected. This indicates a vulnerable regex evaluation.",
						RiskLevel.HIGH, Vulnerability.Confidence.MEDIUM, originalOp, CWEReference.CWE_400,
						List.of("CAPEC-130"), 7.5,
						"Response time increased to " + testTime + "ms when injecting ReDoS payload into "
								+ injectionPoint + ".",
						"Review all regular expressions used for input validation. Avoid using overlapping quantifiers or patterns susceptible to catastrophic backtracking. Implement hard execution time limits on regex evaluation engines.",
						testOp, response, "API Endpoint (Network)", "Denial of Service");
				return Mono.just(vuln);
			}

			if (response.statusCode().value() == 500) {
				// Some frameworks might timeout and return 500
				if (testTime > (baselineTime + 3000)) {
					Vulnerability vuln = createVulnerabilityWithTrace(
							"Regular Expression Denial of Service (ReDoS) - Server Error",
							"The endpoint crashed (HTTP 500) after a delay (" + testTime
									+ "ms) when a catastrophic backtracking payload was injected. This indicates a regex engine timeout or stack overflow.",
							RiskLevel.HIGH, Vulnerability.Confidence.MEDIUM, originalOp, CWEReference.CWE_400,
							List.of("CAPEC-130"), 7.5,
							"Server returned HTTP 500 after " + testTime + "ms when injecting ReDoS payload into "
									+ injectionPoint + ".",
							"Review all regular expressions used for input validation. Avoid using overlapping quantifiers or patterns susceptible to catastrophic backtracking. Implement hard execution time limits on regex evaluation engines.",
							testOp, response, "API Endpoint (Network)", "Denial of Service");
					return Mono.just(vuln);
				}
			}

			return Mono.empty();
		});
	}

}

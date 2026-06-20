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
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import ch.nexsol.orthrusdast.http.ScanHttpClient;
import ch.nexsol.orthrusdast.model.CWEReference;
import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.RiskLevel;
import ch.nexsol.orthrusdast.model.Vulnerability;

/**
 * Scans for Pagination DoS (CWE-770).
 */
@Component
public class PaginationDosScanner implements SecurityScanner {

	private static final Logger log = LoggerFactory.getLogger(PaginationDosScanner.class);

	private static final List<String> PAGINATION_PARAMS = List.of("limit", "size", "page", "per_page", "offset",
			"count", "top", "skip", "max");

	private static final List<String> PAYLOADS = List.of("99999999", "-1", "max");

	private final ScanHttpClient httpClient;

	public PaginationDosScanner(ScanHttpClient httpClient) {
		this.httpClient = httpClient;
	}

	@Override
	public String getId() {
		return "pagination-dos";
	}

	@Override
	public String getName() {
		return "Pagination DoS Scanner";
	}

	@Override
	public ScannerFamily getFamily() {
		return ScannerFamily.LOGIC;
	}

	@Override
	public Flux<Vulnerability> scan(Operation operation) {
		if (operation.queryParams() == null || operation.queryParams().isEmpty()) {
			return Flux.empty();
		}

		List<String> targetParams = new ArrayList<>();
		for (String param : operation.queryParams().keySet()) {
			if (PAGINATION_PARAMS.contains(param.toLowerCase())) {
				targetParams.add(param);
			}
		}

		if (targetParams.isEmpty()) {
			return Flux.empty();
		}

		return Flux.defer(() -> {
			// Get a baseline response time
			return httpClient.send(operation, false).flatMapMany((baselineResponse) -> {
				long baselineTime = baselineResponse.responseTimeMs();

				List<Mono<Vulnerability>> checks = new ArrayList<>();

				for (String param : targetParams) {
					for (String payload : PAYLOADS) {
						Map<String, String> newParams = new HashMap<>(operation.queryParams());
						newParams.put(param, payload);

						Operation testOp = new Operation(operation.url(), operation.method(), operation.headers(),
								newParams, operation.body(), operation.securityRequirements(),
								operation.expectedContentTypes(), operation.authScheme(), operation.templateUrl(),
								operation.sourceNode());

						checks.add(executeAndCheck(testOp, operation, "Query Parameter '" + param + "'", payload,
								baselineTime));
					}
				}

				return Flux.fromIterable(checks).flatMap((mono) -> mono).filter((vuln) -> vuln != null);
			});
		});
	}

	private Mono<Vulnerability> executeAndCheck(Operation testOp, Operation originalOp, String injectionPoint,
			String payload, long baselineTime) {
		return httpClient.send(testOp, false).flatMap((response) -> {
			long testTime = response.responseTimeMs();

			// Detect if the server crashed (e.g. Out of Memory or Database Error)
			if (response.statusCode().value() == 500) {
				Vulnerability vuln = createVulnerabilityWithTrace("Pagination DoS - Server Error",
						"The endpoint crashed (HTTP 500) when a massive pagination size was requested, likely causing an OutOfMemoryError or database failure.",
						RiskLevel.HIGH, Vulnerability.Confidence.HIGH, originalOp, CWEReference.CWE_770,
						List.of("CAPEC-130"), 7.5,
						"Server returned HTTP 500 when injecting payload '" + payload + "' into " + injectionPoint
								+ ".",
						"Enforce strict maximum limits on all pagination parameters (e.g., maximum 100 items per page).",
						testOp, response, "API Endpoint (Network)", "Denial of Service");
				return Mono.just(vuln);
			}

			// Detect if the request took significantly longer than the baseline (Baseline
			// + 5 seconds)
			if (testTime > (baselineTime + 5000)) {
				Vulnerability vuln = createVulnerabilityWithTrace("Pagination DoS - Resource Exhaustion",
						"The endpoint took significantly longer to respond (" + testTime + "ms vs baseline "
								+ baselineTime
								+ "ms) when a massive pagination size was requested. This indicates the database is attempting to fetch too many records.",
						RiskLevel.HIGH, Vulnerability.Confidence.MEDIUM, originalOp, CWEReference.CWE_770,
						List.of("CAPEC-130"), 7.5,
						"Response time increased to " + testTime + "ms when injecting payload '" + payload + "' into "
								+ injectionPoint + ".",
						"Enforce strict maximum limits on all pagination parameters (e.g., maximum 100 items per page). Ensure database queries use bounded limits.",
						testOp, response, "API Endpoint (Network)", "Denial of Service");
				return Mono.just(vuln);
			}

			return Mono.empty();
		});
	}

}

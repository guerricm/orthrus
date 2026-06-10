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
 * Scans for Broken Function Level Authorization (BFLA) (API5:2023).
 */
@Component
public class BflaScanner implements SecurityScanner {

	private final ScanHttpClient httpClient;

	public BflaScanner(ScanHttpClient httpClient) {
		this.httpClient = httpClient;
	}

	@Override
	public String getId() {
		return "bfla";
	}

	@Override
	public String getName() {
		return "Broken Function Level Auth Scanner";
	}

	@Override
	public Flux<Vulnerability> scan(Operation operation) {
		return Flux.defer(() -> {
			org.springframework.http.HttpMethod method = operation.method();
			List<org.springframework.http.HttpMethod> stateChangingMethods = List.of(
					org.springframework.http.HttpMethod.POST, org.springframework.http.HttpMethod.PUT,
					org.springframework.http.HttpMethod.PATCH, org.springframework.http.HttpMethod.DELETE);

			List<org.springframework.http.HttpMethod> methodsToTestDirectly = new java.util.ArrayList<>();
			List<org.springframework.http.HttpMethod> methodsToTestViaHeader = new java.util.ArrayList<>();

			List<org.springframework.http.HttpMethod> supportedMethods = operation.supportedMethods();
			if (supportedMethods == null) {
				supportedMethods = List.of(method);
			}

			for (org.springframework.http.HttpMethod sm : stateChangingMethods) {
				if (sm.equals(method)) {
					continue;
				}
				if (supportedMethods.contains(sm)) {
					methodsToTestViaHeader.add(sm);
				}
				else {
					methodsToTestDirectly.add(sm);
				}
			}

			Flux<Vulnerability> directTests = Flux.fromIterable(methodsToTestDirectly)
				.flatMap(testMethod -> executeBflaCheck(operation, testMethod, operation.headers(),
						"Using " + testMethod.name() + " method directly"));

			Flux<Vulnerability> headerTests = Flux.fromIterable(methodsToTestViaHeader).flatMap(testMethod -> {
				java.util.Map<String, String> overrideHeaders = new java.util.HashMap<>(
						operation.headers() != null ? operation.headers() : new java.util.HashMap<>());
				overrideHeaders.put("X-HTTP-Method-Override", testMethod.name());
				overrideHeaders.put("X-HTTP-Method", testMethod.name());

				return executeBflaCheck(operation, method, overrideHeaders,
						"Using HTTP method override headers to simulate " + testMethod.name());
			});

			return Flux.concat(directTests, headerTests);
		});
	}

	private Flux<Vulnerability> executeBflaCheck(Operation operation, org.springframework.http.HttpMethod testMethod,
			java.util.Map<String, String> testHeaders, String context) {
		Operation testOp = new Operation(operation.url(), testMethod, testHeaders, operation.queryParams(),
				operation.body(), operation.securityRequirements(), operation.expectedContentTypes(),
				operation.authScheme());

		// Fetch baseline to ensure we don't flag if the server just ignores the override
		// header
		return httpClient.send(operation)
			.flatMapMany((baselineResponse) -> httpClient.send(testOp).flatMapMany((response) -> {
				if (response.isSuccessful() && !response.bodyContains("not allowed")
						&& !response.bodyContains("Method Not Allowed")) {

					// If the response is exactly the same as baseline, the server likely
					// ignored the header
					if (baselineResponse.isSuccessful() && response.body().equals(baselineResponse.body())) {
						return Flux.empty();
					}

					Vulnerability vuln = createVulnerabilityWithTrace("Potential Broken Function Level Authorization",
							"The endpoint accepts administrative or state-changing operations via BFLA bypass techniques. Verify if the current user should have this privilege.",
							RiskLevel.HIGH, Vulnerability.Confidence.LOW, operation, CWEReference.CWE_285,
							List.of("CAPEC-115"), 9.8,
							"Server returned " + response.statusCode() + " OK when " + context
									+ " and response differs from baseline.",
							"Ensure function-level access control checks exist for all administrative operations and methods. Reject unexpected HTTP Method Override headers.",
							testOp, response, "API Endpoint (Network)", "Unauthorized Access / Data Exposure");
					return Flux.just(vuln);
				}
				return Flux.empty();
			}));
	}

}

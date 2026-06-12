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
 * Scans for NoSQL Injection (CWE-943).
 */
@Component
public class NoSqlInjectionScanner implements SecurityScanner {

	private final ScanHttpClient httpClient;

	// Using common NoSQL injection payloads that often bypass authentication or where
	// clauses (MongoDB focused)
	private static final String PAYLOAD_1 = "{\"$ne\": null}";

	private static final String PAYLOAD_2 = "{\"$gt\": \"\"}";

	public NoSqlInjectionScanner(ScanHttpClient httpClient) {
		this.httpClient = httpClient;
	}

	@Override
	public String getId() {
		return "nosql-injection";
	}

	@Override
	public String getName() {
		return "NoSQL Injection Scanner";
	}

	@Override
	public ScannerFamily getFamily() {
		return ScannerFamily.INJECTION;
	}

	@Override
	public Flux<Vulnerability> scan(Operation operation) {
		return Flux.defer(() -> {
			return Flux.just(PAYLOAD_1, PAYLOAD_2)
				.concatMap((payload) -> InjectionHelper.generateInjectedOperations(operation, payload)
					.concatMap((test) -> executeNoSqlInjectionTest(operation, test.mutatedOperation(),
							test.injectionPoint(), payload)));
		});
	}

	private Flux<Vulnerability> executeNoSqlInjectionTest(Operation originalOp, Operation testOp, String injectionPoint,
			String payload) {
		return httpClient.send(testOp).flatMapMany((response) -> {
			// Check for typical NoSQL error messages to avoid false positives on generic
			// 500 errors
			if (response.bodyContainsExact("MongoError") || response.bodyContainsExact("MongoServerError")
					|| response.bodyContainsExact("Cast to ObjectId failed")) {
				Vulnerability vuln = createVulnerabilityWithTrace("Potential NoSQL Injection",
						"The endpoint might be vulnerable to NoSQL Injection (e.g., MongoDB) in " + injectionPoint
								+ ".",
						RiskLevel.HIGH, Vulnerability.Confidence.MEDIUM, originalOp, CWEReference.CWE_943,
						List.of("CAPEC-66"), 9.8,
						"Response indicates a NoSQL database error when payload '" + payload + "' was injected.",
						"Validate and sanitize input. Use safe APIs that parameterize queries rather than concatenating strings or blindly passing JSON structures to the database driver.",
						testOp, response, "API Endpoint (Network)", "Unauthorized Access / Data Exposure");
				return Flux.just(vuln);
			}
			return Flux.empty();
		});
	}

}

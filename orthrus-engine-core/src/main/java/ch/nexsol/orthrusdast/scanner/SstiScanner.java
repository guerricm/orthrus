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
 * Scans for Server-Side Template Injection (SSTI) (CWE-1336).
 */
@Component
public class SstiScanner implements SecurityScanner {

	private final ScanHttpClient httpClient;

	// Testing mathematical evaluation which is standard for SSTI.
	// Using a large, unique product to avoid false positives on naturally occurring
	// numbers in IDs/Hashes.
	private static final String PAYLOAD_1 = "{{7384*8931}}";

	private static final String PAYLOAD_2 = "${7384*8931}";

	private static final String EXPECTED_RESULT = "65946504";

	public SstiScanner(ScanHttpClient httpClient) {
		this.httpClient = httpClient;
	}

	@Override
	public String getId() {
		return "ssti";
	}

	@Override
	public String getName() {
		return "Server-Side Template Injection Scanner";
	}

	@Override
	public ScannerFamily getFamily() {
		return ScannerFamily.INJECTION;
	}

	@Override
	public Flux<Vulnerability> scan(Operation operation) {
		return Flux.defer(() -> {
			return Flux.just(PAYLOAD_1, PAYLOAD_2, "<%=" + EXPECTED_RESULT + "%>", "#{7384*8931}", "<%=7384*8931%>")
				.concatMap((payload) -> InjectionHelper.generateInjectedOperations(operation, payload)
					.concatMap((test) -> executeSstiTest(operation, test.mutatedOperation(), test.injectionPoint(),
							payload)));
		});
	}

	private Flux<Vulnerability> executeSstiTest(Operation originalOp, Operation testOp, String injectionPoint,
			String payload) {
		return httpClient.send(testOp).flatMapMany((response) -> {
			// Check if the evaluated math expression (49) is in the response, BUT the
			// original payload is not.
			// If the payload is reflected as is, it's not SSTI.
			if (response.bodyContainsExact(EXPECTED_RESULT) && !response.bodyContainsExact(payload)) {

				Vulnerability vuln = createVulnerabilityWithTrace("Server-Side Template Injection (SSTI)",
						"The endpoint evaluates user input as template code in " + injectionPoint
								+ ", allowing arbitrary code execution on the server.",
						RiskLevel.CRITICAL, Vulnerability.Confidence.HIGH, originalOp, CWEReference.CWE_1336,
						List.of("CAPEC-137"), 9.8,
						"Response contains the evaluated result ('" + EXPECTED_RESULT
								+ "') of the injected template expression '" + payload + "'.",
						"Do not concatenate user input directly into templates. Use logic-less templates or securely pass input as context variables instead of template strings.",
						testOp, response, "API Endpoint (Network)", "Unauthorized Access / Data Exposure");
				return Flux.just(vuln);
			}
			return Flux.empty();
		});
	}

	private String truncate(String text) {
		if (text == null) {
			return "null";
		}
		return (text.length() > 200) ? text.substring(0, 200) + "..." : text;
	}

}

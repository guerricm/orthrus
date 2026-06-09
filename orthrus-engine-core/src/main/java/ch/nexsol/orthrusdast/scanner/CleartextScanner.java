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
 * Scans for Cleartext Transmission (CWE-319).
 */
@Component
public class CleartextScanner implements SecurityScanner {

	private final ScanHttpClient httpClient;

	public CleartextScanner(ScanHttpClient httpClient) {
		this.httpClient = httpClient;
	}

	@Override
	public String getId() {
		return "cleartext-transmission";
	}

	@Override
	public String getName() {
		return "Cleartext Transmission Scanner";
	}

	@Override
	public Flux<Vulnerability> scan(Operation operation) {
		return Flux.defer(() -> {
			String url = operation.url().toLowerCase();

			if (url.startsWith("http://")) {
				// Already cleartext
				boolean isLocal = url.contains("localhost") || url.contains("127.0.0.1");
				return Flux.just(
						createCleartextVuln(operation, operation, isLocal, "Endpoint uses 'http://' scheme natively."));
			}
			else if (url.startsWith("https://")) {
				// Test if it allows HTTP downgrade without redirect
				String httpUrl = "http" + operation.url().substring(5);
				Operation testOp = new Operation(httpUrl, operation.method(), operation.headers(),
						operation.queryParams(), operation.body(), operation.securityRequirements(),
						operation.expectedContentTypes(), operation.authScheme());

				return httpClient.send(testOp)
					.onErrorResume((e) -> reactor.core.publisher.Mono.empty()) // Connection
																				// refused
																				// is good
																				// (HTTP
																				// disabled)
					.flatMapMany((response) -> {
						if (response.isSuccessful()) {
							return Flux.just(createCleartextVuln(operation, testOp, false,
									"Endpoint was accessed over HTTPS but successfully responded to HTTP (port 80) without a redirect to HTTPS."));
						}
						return Flux.empty();
					});
			}

			return Flux.empty();
		});
	}

	private Vulnerability createCleartextVuln(Operation originalOp, Operation testOp, boolean isLocal, String reason) {
		return createVulnerabilityWithTrace("Cleartext Transmission of Sensitive Information",
				"The API endpoint is exposed over unencrypted HTTP. Data sent and received can be intercepted.",
				isLocal ? RiskLevel.INFO : RiskLevel.HIGH, Vulnerability.Confidence.HIGH, originalOp,
				CWEReference.CWE_319, List.of("CAPEC-94"), 7.4, reason,
				"Ensure all API endpoints are exclusively accessible via HTTPS. Implement HSTS (HTTP Strict Transport Security) and enforce 301/302 redirects from HTTP to HTTPS.",
				testOp, null, "API Endpoint (Network)", "Unauthorized Access / Data Exposure");
	}

}

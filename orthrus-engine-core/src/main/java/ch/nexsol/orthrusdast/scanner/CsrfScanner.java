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

import java.util.HashMap;
import java.util.Map;

/**
 * Scans for Cross-Site Request Forgery (CSRF) vulnerabilities (CWE-352).
 */
@Component
public class CsrfScanner implements SecurityScanner {

	private final ScanHttpClient httpClient;

	public CsrfScanner(ScanHttpClient httpClient) {
		this.httpClient = httpClient;
	}

	@Override
	public String getId() {
		return "csrf-protection";
	}

	@Override
	public String getName() {
		return "CSRF Protection Scanner";
	}

	@Override
	public Flux<Vulnerability> scan(Operation operation) {
		return Flux.defer(() -> {
			// Only target state-changing methods
			if (!List.of("POST", "PUT", "DELETE", "PATCH").contains(operation.method().name())) {
				return Flux.empty();
			}

			// Strategy 1: Strip explicit CSRF tokens and set Origin
			Map<String, String> noTokenHeaders = new HashMap<>(
					operation.headers() != null ? operation.headers() : new HashMap<>());
			noTokenHeaders.keySet()
				.removeIf((k) -> k.toLowerCase().contains("csrf") || k.toLowerCase().contains("xsrf")
						|| k.equalsIgnoreCase("X-Requested-With"));
			noTokenHeaders.put("Origin", "https://malicious-website.com");

			Operation testOpNoToken = new Operation(operation.url(), operation.method(), noTokenHeaders,
					operation.queryParams(), operation.body(), operation.securityRequirements(),
					operation.expectedContentTypes(), operation.authScheme());

			// Strategy 2: Content-Type bypass. Send text/plain instead of
			// application/json to bypass preflight CORS checks.
			Map<String, String> plainHeaders = new HashMap<>(noTokenHeaders);
			plainHeaders.put("Content-Type", "text/plain");

			Operation testOpPlain = new Operation(operation.url(), operation.method(), plainHeaders,
					operation.queryParams(), operation.body(), operation.securityRequirements(),
					operation.expectedContentTypes(), operation.authScheme());

			return Flux.concat(httpClient.send(testOpNoToken).flatMapMany((response) -> {
				if (response.isSuccessful()) {
					Vulnerability vuln = createVulnerabilityWithTrace(
							"Cross-Site Request Forgery (CSRF) - Missing Token",
							"The state-changing endpoint allowed a request originating from an untrusted Origin without requiring an explicit Anti-CSRF token in the headers.",
							RiskLevel.MEDIUM, Vulnerability.Confidence.LOW, operation, CWEReference.CWE_352,
							List.of("CAPEC-62"), 6.5,
							"Server accepted the request with Origin: https://malicious-website.com and no CSRF tokens.",
							"Implement Anti-CSRF tokens (Synchronizer Token Pattern) for all state-changing endpoints if using Cookie authentication. Ensure cookies have the SameSite=Lax or Strict attribute.",
							testOpNoToken, response, "API Endpoint (Network)", "Unauthorized Access / Data Exposure");
					return Flux.just(vuln);
				}
				return Flux.empty();
			}), httpClient.send(testOpPlain).flatMapMany((response) -> {
				if (response.isSuccessful()) {
					Vulnerability vuln = createVulnerabilityWithTrace(
							"Cross-Site Request Forgery (CSRF) - Content-Type Bypass",
							"The endpoint relies on CORS preflight requests (e.g. demanding application/json) to prevent CSRF, but it successfully accepts and processes requests with Content-Type: text/plain, which do not trigger preflights.",
							RiskLevel.HIGH, Vulnerability.Confidence.MEDIUM, operation, CWEReference.CWE_352,
							List.of("CAPEC-62"), 7.5,
							"Server processed the state-changing request successfully even when Content-Type was changed to text/plain from a malicious Origin.",
							"Do not rely solely on Content-Type checks or CORS preflights for CSRF protection. Implement explicit CSRF tokens or rely on SameSite cookie attributes.",
							testOpPlain, response, "API Endpoint (Network)", "Unauthorized Access / Data Exposure");
					return Flux.just(vuln);
				}
				return Flux.empty();
			})); // Avoid duplicate reports if both work
		});
	}

}

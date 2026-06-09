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

import ch.nexsol.orthrusdast.http.ScanHttpClient;
import ch.nexsol.orthrusdast.model.CWEReference;
import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.RiskLevel;
import ch.nexsol.orthrusdast.model.Vulnerability;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;

/**
 * Scans for missing Rate Limiting (CWE-799).
 */
@Component
public class RateLimitingScanner implements SecurityScanner {

	private final ScanHttpClient httpClient;

	private static final int REQUEST_COUNT = 30; // Number of rapid requests to send

	public RateLimitingScanner(ScanHttpClient httpClient) {
		this.httpClient = httpClient;
	}

	@Override
	public String getId() {
		return "rate-limiting";
	}

	@Override
	public String getName() {
		return "Rate Limiting Scanner";
	}

	@Override
	public Flux<Vulnerability> scan(Operation operation) {
		return Flux.defer(() -> {
			// We only scan POST/PUT/DELETE for rate limiting to avoid overwhelming GET
			// endpoints during general scans,
			// or specifically target login/auth endpoints.
			boolean isStateChanging = !operation.method().equalsIgnoreCase("GET")
					&& !operation.method().equalsIgnoreCase("OPTIONS");
			boolean isAuthEndpoint = operation.url().toLowerCase().contains("login")
					|| operation.url().toLowerCase().contains("auth")
					|| operation.url().toLowerCase().contains("token");

			if (!isStateChanging && !isAuthEndpoint) {
				return Flux.empty();
			}

			// Send up to 250 requests to try and hit a rate limit
			return Flux.range(1, 250)
				.concatMap((i) -> httpClient.send(operation, false))
				.takeUntil((response) -> response.statusCode().value() == 429)
				.last()
				.flatMapMany((lastResponse) -> {
					if (lastResponse.statusCode().value() != 429) {
						Vulnerability vuln = createVulnerabilityWithTrace("Missing Rate Limiting",
								"The endpoint does not seem to enforce rate limiting. 250 rapid requests were sent without receiving a 429 Too Many Requests response.",
								RiskLevel.MEDIUM, Vulnerability.Confidence.LOW, operation, CWEReference.CWE_799,
								List.of("CAPEC-115"), 5.3,
								"After 250 requests, the server returned status " + lastResponse.statusCode().value()
										+ " instead of 429.",
								"Implement rate limiting using a gateway, WAF, or application logic (e.g. token bucket algorithm).",
								operation, lastResponse, "API Endpoint (Network)",
								"Unauthorized Access / Data Exposure");
						return Flux.just(vuln);
					}
					else {
						// Rate limit was hit! Now test if we can bypass it by spoofing
						// the IP
						Map<String, String> spoofedHeaders = new HashMap<>(
								operation.headers() != null ? operation.headers() : new HashMap<>());
						String randomIp = "203.0.113." + (int) (Math.random() * 255);
						spoofedHeaders.put("X-Forwarded-For", randomIp);
						spoofedHeaders.put("X-Real-IP", randomIp);
						spoofedHeaders.put("Client-IP", randomIp);

						Operation bypassOp = new Operation(operation.url(), operation.method(), spoofedHeaders,
								operation.queryParams(), operation.body(), operation.securityRequirements(),
								operation.expectedContentTypes(), operation.authScheme());

						return httpClient.send(bypassOp, false).flatMapMany((bypassResp) -> {
							if (bypassResp.isSuccessful() || bypassResp.statusCode().value() != 429) {
								Vulnerability bypassVuln = createVulnerabilityWithTrace(
										"Rate Limiting Bypass via IP Spoofing",
										"The endpoint enforces rate limiting, but it can be easily bypassed by spoofing the client IP address using headers like X-Forwarded-For.",
										RiskLevel.HIGH, Vulnerability.Confidence.HIGH, operation, CWEReference.CWE_799, // Still
																														// CWE-799
																														// or
																														// maybe
																														// CWE-348
										List.of("CAPEC-115"), 7.5,
										"Rate limit hit, but a subsequent request with X-Forwarded-For: " + randomIp
												+ " succeeded with status " + bypassResp.statusCode().value() + ".",
										"Configure rate limiting to use the actual network layer client IP, or ensure trusted proxies securely overwrite X-Forwarded-For headers. Do not blindly trust client-provided IP headers for security controls.",
										bypassOp, bypassResp, "API Endpoint (Network)",
										"Unauthorized Access / Data Exposure");
								return Flux.just(bypassVuln);
							}
							return Flux.empty();
						});
					}
				});
		});
	}

}

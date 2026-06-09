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
import ch.nexsol.orthrusdast.model.SecurityScheme;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import java.util.Base64;

/**
 * Scans for JWT "none" algorithm vulnerabilities.
 */
@Component
public class JwtNoneAlgorithmScanner implements SecurityScanner {

	private static final Logger log = LoggerFactory.getLogger(JwtNoneAlgorithmScanner.class);

	private final ScanHttpClient httpClient;

	public JwtNoneAlgorithmScanner(ScanHttpClient httpClient) {
		this.httpClient = httpClient;
	}

	@Override
	public String getId() {
		return "jwt-none-alg";
	}

	@Override
	public String getName() {
		return "JWT 'none' Algorithm Scanner";
	}

	@Override
	public Flux<Vulnerability> scan(Operation operation) {
		return Flux.defer(() -> {
			if (operation.authScheme() == null || operation.authScheme().type() != SecurityScheme.AuthType.BEARER) {
				return Flux.empty();
			}

			String originalToken = operation.authScheme().value();
			String[] parts = originalToken.split("\\.");
			if (parts.length != 3) {
				return Flux.empty(); // Not a standard JWT
			}

			// Test different variations of "none" to bypass naive string matching filters
			return Flux.just("none", "None", "NONE").concatMap((noneAlg) -> {
				String header = "{\"alg\":\"" + noneAlg + "\",\"typ\":\"JWT\"}";
				String encodedHeader = Base64.getUrlEncoder().withoutPadding().encodeToString(header.getBytes());
				String noneAlgToken = encodedHeader + "." + parts[1] + "."; // No
																			// signature

				SecurityScheme noneScheme = SecurityScheme.bearer(noneAlgToken);
				Operation testOp = operation.withAuth(noneScheme);

				return httpClient.send(testOp).flatMapMany((response) -> {
					if (response.isSuccessful() && !response.bodyContains("Unauthorized")
							&& !response.bodyContains("Unauthenticated") && !response.bodyContains("invalid token")) {
						Vulnerability vuln = createVulnerabilityWithTrace("JWT 'none' Algorithm Accepted",
								"The endpoint accepts JWTs signed with the 'none' algorithm (using variation '"
										+ noneAlg + "'), allowing authentication bypass.",
								RiskLevel.CRITICAL, Vulnerability.Confidence.HIGH, operation, CWEReference.CWE_287,
								List.of("CAPEC-115"), 9.8,
								"Endpoint returned " + response.statusCode() + " OK when a JWT with 'alg: " + noneAlg
										+ "' was provided.",
								"Configure your JWT library to explicitly reject the 'none' algorithm and enforce expected algorithms.",
								testOp, response, "API Endpoint (Network)", "Unauthorized Access / Data Exposure");
						return Flux.just(vuln);
					}
					return Flux.empty();
				});
			}).take(1); // Stop on first success
		});
	}

}

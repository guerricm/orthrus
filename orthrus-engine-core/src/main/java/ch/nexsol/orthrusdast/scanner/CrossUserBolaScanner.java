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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;

import ch.nexsol.orthrusdast.http.ScanHttpClient;
import ch.nexsol.orthrusdast.model.CWEReference;
import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.RiskLevel;
import ch.nexsol.orthrusdast.model.ScanConfiguration;
import ch.nexsol.orthrusdast.model.Vulnerability;

/**
 * Advanced BOLA Scanner that uses a secondary user token to test cross-user data access.
 */
@Component
public class CrossUserBolaScanner implements SecurityScanner {

	private static final Logger log = LoggerFactory.getLogger(CrossUserBolaScanner.class);

	private final ScanHttpClient httpClient;

	public CrossUserBolaScanner(ScanHttpClient httpClient) {
		this.httpClient = httpClient;
	}

	@Override
	public String getId() {
		return "cross-user-bola";
	}

	@Override
	public String getName() {
		return "Cross-User BOLA Scanner";
	}

	@Override
	public ScannerFamily getFamily() {
		return ScannerFamily.AUTHENTICATION;
	}

	@Override
	public Flux<Vulnerability> scan(Operation operation) {
		return Flux.defer(() -> Flux.empty());
	}

	@Override
	public Flux<Vulnerability> scan(Operation operation, ScanConfiguration config) {
		// Only run if a secondary auth scheme is provided
		if (config.secondaryAuthScheme() == null) {
			log.debug("Skipping CrossUserBolaScanner because no secondary auth scheme is configured.");
			return Flux.empty();
		}

		// Replay the exact same request with User A's token (baseline) and User B's token
		// (cross-user), then compare. A successful response for User B whose body matches
		// User A's response means User B was served User A's private object: a confirmed
		// BOLA. A successful-but-different response is only a weaker signal.
		Operation userAOp = operation
			.withAuth((config.authScheme() != null) ? config.authScheme() : operation.authScheme());
		Operation crossUserOp = operation.withAuth(config.secondaryAuthScheme());

		return httpClient.send(userAOp)
			.flatMapMany((responseA) -> httpClient.send(crossUserOp).flatMapMany((response) -> {
				boolean userBHasData = response.isSuccessful() && response.body() != null
						&& response.body().length() > 10;
				if (!userBHasData) {
					return Flux.empty();
				}

				boolean sameObject = responseA.body() != null && bodiesMatch(responseA.body(), response.body());

				RiskLevel risk = sameObject ? RiskLevel.HIGH : RiskLevel.MEDIUM;
				Vulnerability.Confidence confidence = sameObject ? Vulnerability.Confidence.HIGH
						: Vulnerability.Confidence.LOW;
				String detail = sameObject
						? "User B received the SAME object data as User A, confirming cross-user object access."
						: "User B received a successful response, but its content differs from User A's; review whether it still exposes data User B should not access.";

				Vulnerability vuln = createVulnerabilityWithTrace("Cross-User Broken Object Level Authorization (BOLA)",
						"The endpoint returned a successful response when accessed with a secondary user's token. "
								+ detail,
						risk, confidence, operation, CWEReference.CWE_639, List.of("CAPEC-17"), 7.5,
						"Server returned " + response.statusCode()
								+ " when requesting User A's resource using User B's authentication token. " + detail,
						"Verify ownership of the requested resource. Ensure the authenticated user has explicit permission to access this specific object ID.",
						operation, response, "API Endpoint (Network)", "Unauthorized Access / Data Exposure");
				return Flux.just(vuln);
			}));
	}

	/**
	 * Compares two response bodies to decide whether they represent the same object. Uses
	 * exact equality after collapsing whitespace, so identical payloads served to two
	 * different users are recognised as the same private resource.
	 * @param a the first body
	 * @param b the second body
	 * @return true if the bodies represent the same object
	 */
	private boolean bodiesMatch(String a, String b) {
		return a.replaceAll("\\s+", " ").trim().equals(b.replaceAll("\\s+", " ").trim());
	}

}

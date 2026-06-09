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

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.stereotype.Component;

import reactor.core.publisher.Flux;

import ch.nexsol.orthrusdast.http.ScanHttpClient;
import ch.nexsol.orthrusdast.model.CWEReference;
import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.RiskLevel;
import ch.nexsol.orthrusdast.model.Vulnerability;

/**
 * Scans for Open Redirect vulnerabilities (CWE-601).
 */
@Component
public class OpenRedirectScanner implements SecurityScanner {

	private final ScanHttpClient httpClient;

	private static final String MALICIOUS_URL = "http://evil-attacker.com";

	public OpenRedirectScanner(ScanHttpClient httpClient) {
		this.httpClient = httpClient;
	}

	@Override
	public String getId() {
		return "open-redirect";
	}

	@Override
	public String getName() {
		return "Open Redirect Scanner";
	}

	@Override
	public Flux<Vulnerability> scan(Operation operation) {
		return Flux.defer(() -> {
			if (operation.queryParams() != null && !operation.queryParams().isEmpty()) {
				return Flux.fromIterable(operation.queryParams().keySet())
					.filter(this::isPotentialRedirectParam)
					.flatMap((paramName) -> testParam(operation, paramName));
			}
			return Flux.empty();
		});
	}

	private boolean isPotentialRedirectParam(String paramName) {
		String lower = paramName.toLowerCase();
		return lower.contains("redirect") || lower.contains("url") || lower.contains("return") || lower.contains("next")
				|| lower.contains("goto") || lower.contains("target");
	}

	private Flux<Vulnerability> testParam(Operation operation, String paramName) {
		String targetHost = "target.com";
		try {
			URI uri = new URI(operation.url());
			targetHost = uri.getHost();
			if (targetHost == null) {
				targetHost = "target.com";
			}
		}
		catch (URISyntaxException ex) {
			// default
		}

		List<String> payloads = List.of("http://evil-attacker.com", "//evil-attacker.com", "\\\\evil-attacker.com",
				"https://" + targetHost + ".evil.com", "javascript:alert(1)");

		return Flux.fromIterable(payloads).concatMap((payload) -> {
			Map<String, String> modifiedParams = new HashMap<>(operation.queryParams());
			modifiedParams.put(paramName, payload);

			Operation testOp = new Operation(operation.url(), operation.method(), operation.headers(), modifiedParams,
					operation.body(), operation.securityRequirements(), operation.expectedContentTypes(),
					operation.authScheme());

			return httpClient.send(testOp).flatMapMany((response) -> {
				// Check if the response is a 3xx redirect AND the Location header matches
				// the malicious URL
				if (response.statusCode().is3xxRedirection()) {
					String locationHeader = response.getHeader("Location");
					if (locationHeader != null && (locationHeader.startsWith(payload)
							|| (payload.startsWith("javascript:") && locationHeader.contains("javascript:")))) {
						Vulnerability vuln = createVulnerabilityWithTrace("Open Redirect - Bypass",
								"The endpoint accepts user-controlled input to determine the target of an HTTP redirect, bypassing protections using payload: "
										+ payload,
								RiskLevel.MEDIUM, Vulnerability.Confidence.HIGH, operation, CWEReference.CWE_601,
								List.of("CAPEC-116"), 6.1,
								"Server responded with a redirect to the injected malicious URL (" + locationHeader
										+ ").",
								"Do not allow users to specify redirect destinations directly. If necessary, use an allowlist or an indirect reference (like an ID mapped to a URL on the server).",
								testOp, response, "API Endpoint (Network)", "Unauthorized Access / Data Exposure");
						return Flux.just(vuln);
					}
				}
				return Flux.empty();
			});
		}).take(1); // Stop after finding the first working bypass
	}

}

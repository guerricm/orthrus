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
import java.util.List;

import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import ch.nexsol.orthrusdast.http.ScanHttpClient;
import ch.nexsol.orthrusdast.http.ScanHttpResponse;
import ch.nexsol.orthrusdast.model.CWEReference;
import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.RiskLevel;
import ch.nexsol.orthrusdast.model.Vulnerability;

/**
 * Scans for missing or misconfigured security headers.
 */
@Component
public class SecurityHeadersScanner implements SecurityScanner {

	private final ScanHttpClient httpClient;

	public SecurityHeadersScanner(ScanHttpClient httpClient) {
		this.httpClient = httpClient;
	}

	@Override
	public String getId() {
		return "security-headers";
	}

	@Override
	public String getName() {
		return "Security Headers Scanner";
	}

	@Override
	public ScannerFamily getFamily() {
		return ScannerFamily.CONFIGURATION;
	}

	@Override
	public Flux<Vulnerability> scan(Operation operation) {
		return Flux.defer(() -> {
			Mono<ScanHttpResponse> normalResponseMono = httpClient.send(operation);

			// Send a bogus method to trigger a container-level error page (e.g., 405 or
			// 400) which often leaks Server headers
			Operation errorOp = new Operation(operation.url(), HttpMethod.valueOf("BOGUS_METHOD_TEST"),
					operation.headers(), operation.queryParams(), operation.body(), operation.securityRequirements(),
					operation.expectedContentTypes(), operation.authScheme());
			Mono<ScanHttpResponse> errorResponseMono = httpClient.send(errorOp, false)
				.onErrorResume((e) -> Mono.empty());

			return Flux.merge(normalResponseMono, errorResponseMono).flatMap((response) -> {
				List<Vulnerability> vulns = new ArrayList<>();

				// Only check missing security headers on the 2xx normal response to avoid
				// false positives on error pages
				if (response.isSuccessful()) {
					checkHeader(response, "Strict-Transport-Security", "HSTS", CWEReference.CWE_693, operation, vulns);
					checkHeader(response, "X-Content-Type-Options", "X-Content-Type-Options", CWEReference.CWE_693,
							operation, vulns);
					checkHeader(response, "X-Frame-Options", "X-Frame-Options", CWEReference.CWE_1021, operation,
							vulns);
					checkHeader(response, "Content-Security-Policy", "CSP", CWEReference.CWE_693, operation, vulns);
					checkHeader(response, "Permissions-Policy", "Permissions-Policy", CWEReference.CWE_693, operation,
							vulns);
					checkHeader(response, "Referrer-Policy", "Referrer-Policy", CWEReference.CWE_693, operation, vulns);
				}

				// Server info leakage can happen on both normal and error responses!
				checkServerInfoLeakage(response, operation, vulns);

				return Flux.fromIterable(vulns);
			}).distinct(Vulnerability::name); // Avoid duplicate info leakage reports
		});
	}

	private void checkHeader(ScanHttpResponse response, String headerName, String shortName, CWEReference cwe,
			Operation operation, List<Vulnerability> vulns) {
		if (!response.hasHeader(headerName)) {
			vulns.add(createVulnerabilityWithTrace("Missing Security Header: " + shortName,
					"The HTTP response does not contain the '" + headerName + "' security header.", RiskLevel.LOW,
					Vulnerability.Confidence.HIGH, operation, cwe, List.of("CAPEC-310"), 4.3,
					"Header '" + headerName + "' is missing from the response.",
					"Configure your web server or application framework to include the '" + headerName
							+ "' header in all responses.",
					operation, response, "API Endpoint (Network)", "Unauthorized Access / Data Exposure"));
		}
		else {
			String headerValue = response.getHeader(headerName);
			if ("Content-Security-Policy".equalsIgnoreCase(headerName)) {
				if (headerValue != null
						&& (headerValue.contains("unsafe-inline") || headerValue.contains("unsafe-eval"))) {
					boolean hasUnsafeEval = headerValue.contains("unsafe-eval");
					boolean hasUnsafeInlineScript = headerValue.matches("(?i).*script-src[^;]*'unsafe-inline'.*")
							|| headerValue.matches("(?i).*default-src[^;]*'unsafe-inline'.*");
					boolean hasUnsafeInlineStyle = headerValue.matches("(?i).*style-src[^;]*'unsafe-inline'.*");

					boolean isRisky = hasUnsafeEval || hasUnsafeInlineScript
							|| (!hasUnsafeEval && !hasUnsafeInlineScript && !hasUnsafeInlineStyle);

					RiskLevel risk = RiskLevel.MEDIUM;
					String desc = "The Content-Security-Policy header contains 'unsafe-inline' or 'unsafe-eval', which significantly reduces the protection against XSS attacks.";
					double cvss = 5.4;

					String contentType = response.getHeader("Content-Type");
					boolean isJson = contentType != null && contentType.toLowerCase().contains("json");

					if (!isRisky && hasUnsafeInlineStyle && isJson) {
						risk = RiskLevel.INFO;
						cvss = 0.0;
						desc = "The Content-Security-Policy header contains 'unsafe-inline' for 'style-src'. Since this API response is JSON ("
								+ contentType
								+ "), the risk of CSS injection is minimal. However, best practices still recommend removing it.";
					}

					vulns.add(createVulnerabilityWithTrace("Weak Security Header: CSP", desc, risk,
							Vulnerability.Confidence.HIGH, operation, cwe, List.of("CAPEC-63"), cvss,
							"CSP value contains unsafe directives: " + headerValue,
							"Remove 'unsafe-inline' and 'unsafe-eval' from your CSP and use nonces or hashes instead.",
							operation, response, "API Endpoint (Network)", "Unauthorized Access / Data Exposure"));
				}
			}
			else if ("Strict-Transport-Security".equalsIgnoreCase(headerName)) {
				if (headerValue != null
						&& (!headerValue.contains("max-age") || !headerValue.contains("includeSubDomains"))) {
					vulns.add(createVulnerabilityWithTrace("Weak Security Header: HSTS",
							"The Strict-Transport-Security (HSTS) header is present but misconfigured (missing max-age or includeSubDomains).",
							RiskLevel.LOW, Vulnerability.Confidence.HIGH, operation, cwe, List.of("CAPEC-310"), 4.3,
							"HSTS value is misconfigured: " + headerValue,
							"Ensure HSTS has a large max-age (e.g., 31536000) and includes 'includeSubDomains'.",
							operation, response, "API Endpoint (Network)", "Unauthorized Access / Data Exposure"));
				}
			}
		}
	}

	private void checkServerInfoLeakage(ScanHttpResponse response, Operation operation, List<Vulnerability> vulns) {
		List<String> leakyHeaders = List.of("Server", "X-Powered-By", "X-AspNet-Version");
		for (String header : leakyHeaders) {
			String value = response.getHeader(header);
			if (value != null && !value.isBlank()) {
				// For Server header, we only care if it leaks a version or specific
				// framework, not just "nginx"
				if (header.equals("Server") && !value.matches(".*[0-9/].*")) {
					continue; // Generic server name like "cloudflare" or "nginx" without
								// version is mostly fine
				}

				vulns.add(createVulnerabilityWithTrace("Information Exposure: " + header + " Header",
						"The server leaks version information or technology stack details via the '" + header
								+ "' header.",
						RiskLevel.LOW, Vulnerability.Confidence.HIGH, operation, CWEReference.CWE_200,
						List.of("CAPEC-118"), 3.7, "Header '" + header + "' reveals: " + value,
						"Configure your web server to remove or mask the '" + header + "' header.", operation, response,
						"API Endpoint (Network)", "Unauthorized Access / Data Exposure"));
			}
		}
	}

}

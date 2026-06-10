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

import org.springframework.http.HttpMethod;

/**
 * Scans for HTTP Method Tampering (CWE-650).
 */
@Component
public class HttpMethodTamperingScanner implements SecurityScanner {

	private final ScanHttpClient httpClient;

	// Methods that are typically not expected for data retrieval/modification if not
	// explicitly defined
	private static final String[] UNUSUAL_METHODS = { "TRACE", "TRACK", "DEBUG" };

	public HttpMethodTamperingScanner(ScanHttpClient httpClient) {
		this.httpClient = httpClient;
	}

	@Override
	public String getId() {
		return "method-tampering";
	}

	@Override
	public String getName() {
		return "HTTP Method Tampering Scanner";
	}

	@Override
	public Flux<Vulnerability> scan(Operation operation) {
		return Flux.defer(() -> {
			Flux<Vulnerability> unusualMethodVulns = Flux.fromArray(UNUSUAL_METHODS)
				.flatMap((method) -> testMethod(operation, method));

			Flux<Vulnerability> overrideVulns = Flux.empty();

			// Test X-HTTP-Method-Override bypass
			String originalMethod = operation.method().name();
			if ("POST".equals(originalMethod) || "PUT".equals(originalMethod) || "DELETE".equals(originalMethod)
					|| "PATCH".equals(originalMethod)) {
				// Send as GET but with X-HTTP-Method-Override: POST
				Map<String, String> overrideHeaders = new HashMap<>(
						operation.headers() != null ? operation.headers() : new HashMap<>());
				overrideHeaders.put("X-HTTP-Method-Override", originalMethod);
				overrideHeaders.put("X-HTTP-Method", originalMethod);
				overrideHeaders.put("X-Method-Override", originalMethod);

				Operation overrideOp = new Operation(operation.url(), HttpMethod.GET, overrideHeaders,
						operation.queryParams(), operation.body(), operation.securityRequirements(),
						operation.expectedContentTypes(), operation.authScheme());

				overrideVulns = httpClient.send(overrideOp).flatMapMany((response) -> {
					if (response.isSuccessful()) {
						Vulnerability vuln = createVulnerabilityWithTrace("HTTP Method Override Bypass",
								"The endpoint accepted a GET request but processed it as a " + originalMethod
										+ " because of the X-HTTP-Method-Override headers. This can bypass WAF rules or naive authorization checks that only inspect the request line method.",
								RiskLevel.MEDIUM, Vulnerability.Confidence.MEDIUM, operation, CWEReference.CWE_650,
								List.of("CAPEC-274"), 5.3,
								"Server responded with " + response.statusCode()
										+ " when sending a GET request with X-HTTP-Method-Override: " + originalMethod
										+ ".",
								"Disable support for HTTP method override headers unless strictly necessary for legacy clients.",
								overrideOp, response, "API Endpoint (Network)", "Unauthorized Access / Data Exposure");
						return Flux.just(vuln);
					}
					return Flux.empty();
				});
			}

			return Flux.concat(unusualMethodVulns, overrideVulns);
		});
	}

	private Flux<Vulnerability> testMethod(Operation operation, String method) {
		Operation testOp = new Operation(operation.url(), HttpMethod.valueOf(method), operation.headers(),
				operation.queryParams(), null, // No
				// body
				// for
				// these
				// methods
				// usually
				operation.securityRequirements(), operation.expectedContentTypes(), operation.authScheme());

		return httpClient.send(testOp).flatMapMany((response) -> {
			// If TRACE is enabled and returns 200, it's a known vulnerability (Cross-Site
			// Tracing - XST)
			if ("TRACE".equals(method) && response.isSuccessful() && response.bodyContains("TRACE /")) {
				Vulnerability vuln = createVulnerabilityWithTrace("HTTP TRACE Method Enabled",
						"The server supports the HTTP TRACE method, which can be exploited for Cross-Site Tracing (XST) attacks.",
						RiskLevel.MEDIUM, Vulnerability.Confidence.HIGH, operation, CWEReference.CWE_650,
						List.of("CAPEC-274"), 5.3,
						"Server responded with 200 OK and reflected the request when using the TRACE method.",
						"Disable the HTTP TRACE method on the web server.", testOp, response, "API Endpoint (Network)",
						"Unauthorized Access / Data Exposure");
				return Flux.just(vuln);
			}
			else if (!"TRACE".equals(method) && response.isSuccessful()) {
				// Some other unusual method worked
				Vulnerability vuln = createVulnerabilityWithTrace("Unusual HTTP Method Supported",
						"The server successfully processes requests using the '" + method
								+ "' HTTP method, which might lead to bypasses.",
						RiskLevel.LOW, Vulnerability.Confidence.MEDIUM, operation, CWEReference.CWE_650,
						List.of("CAPEC-274"), 5.3,
						"Server responded with " + response.statusCode() + " when using the " + method + " method.",
						"Restrict accepted HTTP methods to only those strictly necessary (e.g., GET, POST, PUT, DELETE).",
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

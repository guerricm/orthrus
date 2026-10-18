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

import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import ch.nexsol.orthrus.protocol.node.CWEReference;
import ch.nexsol.orthrus.protocol.node.RiskLevel;
import ch.nexsol.orthrus.protocol.node.Vulnerability;
import ch.nexsol.orthrusdast.http.ScanHttpClient;
import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.scanner.oast.OastService;

/**
 * Scans for Host Header Injection (CWE-114 / CWE-644).
 */
@Component
public class HostHeaderInjectionScanner implements SecurityScanner {

	private static final String REMEDIATION = "Validate and sanitize all HTTP headers. Avoid reflecting the Host "
			+ "header in links, password resets, or cache keys without strict allowlist validation.";

	private final ScanHttpClient httpClient;

	private final OastService oastService;

	public HostHeaderInjectionScanner(ScanHttpClient httpClient, OastService oastService) {
		this.httpClient = httpClient;
		this.oastService = oastService;
	}

	@Override
	public String getId() {
		return "host-header-injection";
	}

	@Override
	public String getName() {
		return "Host Header Injection Scanner";
	}

	@Override
	public ScannerFamily getFamily() {
		return ScannerFamily.LOGIC;
	}

	@Override
	public Flux<Vulnerability> scan(Operation operation) {
		return Flux.defer(() -> oastService.createSession().flatMapMany((session) -> {

			String oastDomain = session.domain();

			// Payload 1: Overriding the Host header directly
			Map<String, String> payload1Headers = Map.of("Host", oastDomain);

			// Payload 2: Using X-Forwarded-Host and Forwarded headers
			Map<String, String> payload2Headers = Map.of("X-Forwarded-Host", oastDomain, "Forwarded",
					"host=" + oastDomain);

			Mono<Vulnerability> check1 = executeAndCheck(operation, payload1Headers, "Host header", oastDomain);
			Mono<Vulnerability> check2 = executeAndCheck(operation, payload2Headers, "X-Forwarded-Host header",
					oastDomain);

			// One direct finding per operation: the most severe of the two injection
			// points.
			Flux<Vulnerability> directChecks = Flux.concat(check1, check2)
				.reduce((first, second) -> (second.riskLevel().compareTo(first.riskLevel()) > 0) ? second : first)
				.flux();

			Flux<Vulnerability> blindChecks = oastService.pollInteractions(session)
				.map((interaction) -> createVulnerabilityWithTrace(
						"Host Header Injection - Cache Poisoning / Blind SSRF",
						"The endpoint attempted to contact the injected Host header domain (" + oastDomain
								+ "). This indicates a severe vulnerability where the backend trusts the Host header for internal routing or caching.",
						RiskLevel.HIGH, Vulnerability.Confidence.HIGH, operation, CWEReference.CWE_114,
						List.of("CAPEC-141"), 7.5,
						"Received an interaction from " + interaction.remoteAddress() + " via " + interaction.protocol()
								+ " to the injected OAST domain.",
						"Validate and sanitize all HTTP headers. Avoid reflecting the Host header in links, password resets, or cache keys without strict allowlist validation.",
						operation, null, "API Endpoint (Network)", "Unauthorized Access / Data Exposure"));

			return Flux.concat(directChecks, blindChecks);
		}));
	}

	/**
	 * Sends the injected headers and judges the target's own answer. Redirects are not
	 * followed: a proxy answering an unknown Host with a redirect to it would otherwise
	 * send the client to the injected domain, and that client-side failure is no evidence
	 * about the target.
	 * @param operation the probed operation
	 * @param extraHeaders the injected headers
	 * @param injectionPoint how the domain was injected, for the evidence
	 * @param injectedDomain the domain to look for
	 * @return the finding, or empty when the target ignored the injection
	 */
	private Mono<Vulnerability> executeAndCheck(Operation operation, Map<String, String> extraHeaders,
			String injectionPoint, String injectedDomain) {
		return httpClient.sendWithoutRedirects(operation, extraHeaders).flatMap((response) -> {
			Operation testOp = withHeaders(operation, extraHeaders);
			if (response.bodyContainsExact(injectedDomain)) {
				return Mono.just(createVulnerabilityWithTrace("Host Header Injection - Content Reflection",
						"The endpoint reflects the injected Host header (" + injectedDomain
								+ ") in its response. This can lead to Password Reset Poisoning or cache poisoning.",
						RiskLevel.MEDIUM, Vulnerability.Confidence.HIGH, operation, CWEReference.CWE_644,
						List.of("CAPEC-141"), 5.4,
						"Server reflected the injected domain ('" + injectedDomain + "') when it was supplied via the "
								+ injectionPoint + ".",
						REMEDIATION, testOp, response, "API Endpoint (Network)",
						"Unintended Behavior / Content Spoofing"));
			}
			String location = response.getHeader(HttpHeaders.LOCATION);
			if (!response.clientError() && response.statusCode().is3xxRedirection() && location != null
					&& location.contains(injectedDomain)) {
				return Mono.just(createVulnerabilityWithTrace("Host Header Injection - Reflected in Redirect",
						"The endpoint builds its redirect from the injected Host header (" + injectedDomain
								+ "). Usually a front proxy behaviour; it only becomes exploitable when such a "
								+ "redirect is cached or reaches a victim (cache poisoning, open redirect).",
						RiskLevel.LOW, Vulnerability.Confidence.HIGH, operation, CWEReference.CWE_644,
						List.of("CAPEC-141"), 3.1,
						"HTTP " + response.statusCode().value() + " with Location: " + location + " when the "
								+ injectionPoint + " was set to '" + injectedDomain + "'.",
						REMEDIATION, testOp, response, "API Endpoint (Network)",
						"Unintended Behavior / Content Spoofing"));
			}
			return Mono.empty();
		});
	}

	private static Operation withHeaders(Operation operation, Map<String, String> extraHeaders) {
		Map<String, String> mergedHeaders = new HashMap<>(
				(operation.headers() != null) ? operation.headers() : Map.of());
		mergedHeaders.putAll(extraHeaders);
		return new Operation(operation.url(), operation.method(), mergedHeaders, operation.queryParams(),
				operation.body(), operation.securityRequirements(), operation.expectedContentTypes(),
				operation.authScheme(), operation.templateUrl(), operation.sourceNode());
	}

}

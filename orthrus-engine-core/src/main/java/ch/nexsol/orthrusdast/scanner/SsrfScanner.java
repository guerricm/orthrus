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
import ch.nexsol.orthrusdast.scanner.oast.OastService;

/**
 * Scans for SSRF (Server-Side Request Forgery) (CWE-918).
 */
@Component
public class SsrfScanner implements SecurityScanner {

	private final ScanHttpClient httpClient;

	private final OastService oastService;

	public SsrfScanner(ScanHttpClient httpClient, OastService oastService) {
		this.httpClient = httpClient;
		this.oastService = oastService;
	}

	@Override
	public String getId() {
		return "ssrf";
	}

	@Override
	public String getName() {
		return "SSRF Scanner";
	}

	@Override
	public Flux<Vulnerability> scan(Operation operation) {
		return Flux.defer(() -> {
			return oastService.createSession().flatMapMany((session) -> {

				// Payloads: AWS Metadata and Blind OAST URL
				List<String> payloads = List.of("http://169.254.169.254/latest/meta-data/",
						"http://" + session.domain(), "file:///etc/passwd");

				Flux<Vulnerability> errorBasedVulns = Flux.fromIterable(payloads).concatMap((payload) -> {
					return InjectionHelper.generateInjectedOperations(operation, payload)
						.concatMap((test) -> httpClient.send(test.mutatedOperation()).flatMapMany((response) -> {
							if (response.bodyContains("ami-id") || response.bodyContains("instance-id")
									|| response.bodyContains("local-hostname") || response.bodyContains("root:x:0:0")) {
								Vulnerability vuln = createVulnerabilityWithTrace(
										"Server-Side Request Forgery (SSRF) - Direct",
										"The endpoint is vulnerable to direct SSRF. It fetched local files or AWS metadata.",
										RiskLevel.CRITICAL, Vulnerability.Confidence.HIGH, operation,
										CWEReference.CWE_918, List.of("CAPEC-664"), 8.6,
										"Response contains sensitive system data when injecting " + payload + " into "
												+ test.injectionPoint() + ".",
										"Validate and sanitize all user-supplied URLs. Use an allowlist of permitted domains. Disable fetching of file:// URLs.",
										test.mutatedOperation(), response, "API Endpoint (Network)",
										"Unauthorized Access / Data Exposure");
								return Flux.just(vuln);
							}
							return Flux.empty();
						}));
				});

				Flux<Vulnerability> blindVulns = oastService.pollInteractions(session)
					.map((interaction) -> createVulnerabilityWithTrace(
							"Server-Side Request Forgery (SSRF) - Blind OAST",
							"The endpoint is vulnerable to blind SSRF. It made an out-of-band request to the injected OAST domain.",
							RiskLevel.CRITICAL, Vulnerability.Confidence.HIGH, operation, CWEReference.CWE_918,
							List.of("CAPEC-664"), 8.6,
							"Received an interaction from " + interaction.remoteAddress() + " via "
									+ interaction.protocol() + " to the injected OAST domain.",
							"Validate and sanitize all user-supplied URLs. Ensure the server does not blindly fetch remote resources based on user input.",
							operation, null, "API Endpoint (Network)", "Unauthorized Access / Data Exposure"));

				return Flux.concat(errorBasedVulns, blindVulns);
			});
		});
	}

}

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

import org.springframework.stereotype.Component;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import ch.nexsol.orthrusdast.http.ScanHttpClient;
import ch.nexsol.orthrusdast.http.ScanHttpResponse;
import ch.nexsol.orthrusdast.model.CWEReference;
import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.RiskLevel;
import ch.nexsol.orthrusdast.model.Vulnerability;

import ch.nexsol.orthrusdast.scanner.oast.OastService;

/**
 * Scans for OS Command Injection vulnerabilities (CWE-78).
 */
@Component
public class CommandInjectionScanner implements SecurityScanner {

	private final ScanHttpClient httpClient;

	// Using an arithmetic evaluation payload to prevent false positives from simple
	// string reflection.
	// If the application simply echoes the input, the response will contain
	// "$((837492+561837))".
	// If the application is truly vulnerable, the shell will evaluate the arithmetic and
	// output "1399329".
	private static final String CALC_PAYLOAD_CONTENT = "$((837492+561837))";

	private static final String CALC_RESULT = "1399329";

	private static final String[] PAYLOADS = { "; echo " + CALC_PAYLOAD_CONTENT, "| echo " + CALC_PAYLOAD_CONTENT,
			"& echo " + CALC_PAYLOAD_CONTENT, "$(echo " + CALC_PAYLOAD_CONTENT + ")",
			"`echo " + CALC_PAYLOAD_CONTENT + "`" };

	private final OastService oastService;

	public CommandInjectionScanner(ScanHttpClient httpClient, OastService oastService) {
		this.httpClient = httpClient;
		this.oastService = oastService;
	}

	@Override
	public String getId() {
		return "cmd-injection";
	}

	@Override
	public String getName() {
		return "OS Command Injection Scanner";
	}

	@Override
	public ScannerFamily getFamily() {
		return ScannerFamily.INJECTION;
	}

	@Override
	public Flux<Vulnerability> scan(Operation operation) {
		return Flux.defer(() -> {
			return oastService.createSession().flatMapMany((oastSession) -> {
				String oastPayloadContent = "curl http://" + oastSession.domain();
				String timePayloadContent = "sleep 5";

				List<String> allPayloads = new ArrayList<>(List.of(PAYLOADS));

				// Add OAST & Time-based payloads
				for (String prefix : new String[] { "; ", "| ", "& ", "$(", "`" }) {
					String suffix = prefix.contains("(") ? ")" : (prefix.contains("`") ? "`" : "");
					allPayloads.add(prefix + oastPayloadContent + suffix);
					allPayloads.add(prefix + timePayloadContent + suffix);
				}

				// Measure a timing baseline once so time-based detection can compare
				// against the endpoint's natural latency instead of a fixed threshold.
				Mono<Long> baseline = httpClient.send(operation)
					.map(ScanHttpResponse::responseTimeMs)
					.onErrorReturn(0L);

				Flux<Vulnerability> scanVulns = baseline.flatMapMany((baselineMs) -> Flux.fromIterable(allPayloads)
					.concatMap((payload) -> InjectionHelper.generateInjectedOperations(operation, payload)
						.concatMap((test) -> executeCommandInjectionTest(operation, test.mutatedOperation(),
								test.injectionPoint(), payload, baselineMs))));

				return scanVulns.concatWith(oastService.pollInteractions(oastSession)
					.map((interaction) -> createVulnerabilityWithTrace("Out-Of-Band (Blind) OS Command Injection",
							"The endpoint triggered a DNS/HTTP request to the OAST server during command injection payload execution.",
							RiskLevel.CRITICAL, Vulnerability.Confidence.HIGH, operation, CWEReference.CWE_78,
							List.of("CAPEC-88"), 9.8,
							"An interaction was received from " + interaction.remoteAddress() + " via "
									+ interaction.protocol(),
							"Avoid invoking OS commands directly. Strictly sanitize and parameterize all input.",
							operation, null, "API Endpoint (Network)", "Unauthorized Access / Data Exposure")));
			});
		});
	}

	private Flux<Vulnerability> executeCommandInjectionTest(Operation originalOp, Operation testOp,
			String injectionPoint, String payload, long baselineMs) {
		return httpClient.send(testOp).flatMapMany((response) -> {
			// Time-Based Blind Detection, validated against the measured baseline.
			int status = response.statusCode().value();
			if (payload.contains("sleep")
					&& DetectionUtils.isTimeBasedHit(response.responseTimeMs(), baselineMs, status)) {
				Vulnerability vuln = createVulnerabilityWithTrace("Time-Based Blind OS Command Injection",
						"The endpoint took " + response.responseTimeMs() + "ms to respond (baseline " + baselineMs
								+ "ms), indicating a potential Time-Based Blind Command Injection in " + injectionPoint
								+ ".",
						RiskLevel.CRITICAL, Vulnerability.Confidence.HIGH, originalOp, CWEReference.CWE_78,
						List.of("CAPEC-88"), 9.8,
						"Response was delayed by " + response.responseTimeMs() + "ms (baseline " + baselineMs
								+ "ms) when payload '" + payload + "' was injected.",
						"Avoid invoking OS commands directly. Strictly sanitize and parameterize all input.", testOp,
						response, "API Endpoint (Network)", "Unauthorized Access / Data Exposure");
				return Flux.just(vuln);
			}

			// Content-Based Detection (Arithmetic execution)
			if (response.bodyContainsExact(CALC_RESULT) && !response.bodyContainsExact(CALC_PAYLOAD_CONTENT)) {
				Vulnerability vuln = createVulnerabilityWithTrace("OS Command Injection",
						"The endpoint appears vulnerable to OS Command Injection in " + injectionPoint + ".",
						RiskLevel.CRITICAL, Vulnerability.Confidence.HIGH, originalOp, CWEReference.CWE_78,
						List.of("CAPEC-88"), 9.8,
						"Response contains the evaluated arithmetic result '" + CALC_RESULT
								+ "' from the injected payload.",
						"Avoid invoking OS commands directly. Strictly sanitize and parameterize all input.", testOp,
						response, "API Endpoint (Network)", "Unauthorized Access / Data Exposure");
				return Flux.just(vuln);
			}
			return Flux.empty();
		});
	}

}

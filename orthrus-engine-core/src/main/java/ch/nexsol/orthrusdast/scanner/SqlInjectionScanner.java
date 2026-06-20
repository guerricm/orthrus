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
import reactor.core.publisher.Mono;

import ch.nexsol.orthrusdast.http.ScanHttpClient;
import ch.nexsol.orthrusdast.http.ScanHttpResponse;
import ch.nexsol.orthrusdast.model.CWEReference;
import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.RiskLevel;
import ch.nexsol.orthrusdast.model.Vulnerability;
import ch.nexsol.orthrusdast.scanner.oast.OastService;
import ch.nexsol.orthrusdast.scanner.payload.PayloadLoaderService;
import ch.nexsol.orthrusdast.scanner.payload.PayloadMutator;

/**
 * Scans for SQL Injection vulnerabilities (CWE-89).
 */
@Component
public class SqlInjectionScanner implements SecurityScanner {

	private static final Logger log = LoggerFactory.getLogger(SqlInjectionScanner.class);

	private final ScanHttpClient httpClient;

	private final PayloadLoaderService payloadLoader;

	private final PayloadMutator payloadMutator;

	private final OastService oastService;

	public SqlInjectionScanner(ScanHttpClient httpClient, PayloadLoaderService payloadLoader,
			PayloadMutator payloadMutator, OastService oastService) {
		this.httpClient = httpClient;
		this.payloadLoader = payloadLoader;
		this.payloadMutator = payloadMutator;
		this.oastService = oastService;
	}

	@Override
	public String getId() {
		return "sqli";
	}

	@Override
	public String getName() {
		return "SQL Injection Scanner";
	}

	@Override
	public ScannerFamily getFamily() {
		return ScannerFamily.INJECTION;
	}

	@Override
	public Flux<Vulnerability> scan(Operation operation) {
		return Flux.defer(() -> {
			log.debug("Scanning for SQL Injection: {}", operation.url());

			return oastService.createSession().flatMapMany((oastSession) -> {
				// Gather the error signatures and a timing baseline once per endpoint.
				Mono<List<String>> sqlErrors = payloadLoader.getPayloads("sql-errors").collectList();
				Mono<Long> baseline = httpClient.send(operation)
					.map(ScanHttpResponse::responseTimeMs)
					.onErrorReturn(0L);

				return Mono.zip(sqlErrors, baseline).flatMapMany((ctx) -> {
					List<String> signatures = ctx.getT1();
					long baselineMs = ctx.getT2();

					Flux<Vulnerability> scanVulns = payloadLoader.getPayloads("sqli").concatMap((rawPayload) -> {
						String oastPayload = rawPayload.replace("{{OAST_HOST}}", oastSession.domain());
						String payload = payloadMutator.mutate(oastPayload, PayloadMutator.Context.URL_PARAM);
						return InjectionHelper.generateInjectedOperations(operation, payload)
							.concatMap((test) -> executeSqlInjectionTest(operation, test.mutatedOperation(),
									test.injectionPoint(), payload, baselineMs, signatures));
					});

					return scanVulns.concatWith(oastService.pollInteractions(oastSession)
						.map((interaction) -> createVulnerabilityWithTrace("Out-Of-Band (Blind) SQL Injection",
								"The endpoint triggered a DNS/HTTP request to the OAST server during SQL injection payload execution.",
								RiskLevel.CRITICAL, Vulnerability.Confidence.HIGH, operation, CWEReference.CWE_89,
								List.of("CAPEC-66"), 9.8,
								"An interaction was received from " + interaction.remoteAddress() + " via "
										+ interaction.protocol() + " for query: " + interaction.queryType(),
								"Use parameterized queries or prepared statements.", operation, null,
								"API Endpoint (Network)", "Unauthorized Access / Data Exposure")));
				});
			});
		});
	}

	private Flux<Vulnerability> executeSqlInjectionTest(Operation originalOp, Operation testOp, String injectionPoint,
			String payload, long baselineMs, List<String> sqlErrorSignatures) {
		return httpClient.send(testOp).flatMapMany((response) -> {
			// Time-Based Blind Detection, validated against the measured baseline.
			boolean isTimeBasedPayload = payload.toLowerCase().contains("sleep")
					|| payload.toLowerCase().contains("waitfor");
			int status = response.statusCode().value();
			if (isTimeBasedPayload && DetectionUtils.isTimeBasedHit(response.responseTimeMs(), baselineMs, status)) {
				Vulnerability vuln = createVulnerabilityWithTrace("Time-Based Blind SQL Injection",
						"The endpoint took " + response.responseTimeMs() + "ms to respond (baseline " + baselineMs
								+ "ms), indicating a potential Time-Based Blind SQL Injection in " + injectionPoint
								+ ".",
						RiskLevel.CRITICAL, Vulnerability.Confidence.HIGH, originalOp, CWEReference.CWE_89,
						List.of("CAPEC-66"), 9.8,
						"Response was delayed by " + response.responseTimeMs() + "ms (baseline " + baselineMs
								+ "ms) when payload '" + payload + "' was injected.",
						"Use parameterized queries or prepared statements.", testOp, response, "API Endpoint (Network)",
						"Unauthorized Access / Data Exposure");
				return Flux.just(vuln);
			}

			// Content-Based Detection (database error signatures).
			if (DetectionUtils.containsAny(response.body(), sqlErrorSignatures)) {
				Vulnerability vuln = createVulnerabilityWithTrace("Potential Error-Based SQL Injection",
						"The endpoint might be vulnerable to Error-Based SQL Injection in " + injectionPoint + ".",
						RiskLevel.HIGH, Vulnerability.Confidence.MEDIUM, originalOp, CWEReference.CWE_89,
						List.of("CAPEC-66"), 9.8,
						"Response indicates a database error when payload '" + payload + "' was injected.",
						"Use parameterized queries or prepared statements and disable verbose error messages.", testOp,
						response, "API Endpoint (Network)", "Unauthorized Access / Data Exposure");
				return Flux.just(vuln);
			}
			return Flux.empty();
		});
	}

}

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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import reactor.core.publisher.Flux;

import ch.nexsol.orthrusdast.http.ScanHttpClient;
import ch.nexsol.orthrusdast.model.CWEReference;
import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.RiskLevel;
import ch.nexsol.orthrusdast.model.Vulnerability;

/**
 * Scans GraphQL Operations for Injection Vulnerabilities (SQLi, XSS, CmdInj) by injecting
 * payloads into GraphQL variables.
 */
@Component
public class GraphqlInjectionScanner implements SecurityScanner {

	private static final Logger log = LoggerFactory.getLogger(GraphqlInjectionScanner.class);

	private final ScanHttpClient httpClient;

	private final ObjectMapper objectMapper = new ObjectMapper();

	private final ch.nexsol.orthrusdast.scanner.payload.PayloadLoaderService payloadLoader;

	private final ch.nexsol.orthrusdast.scanner.payload.PayloadMutator payloadMutator;

	private final ch.nexsol.orthrusdast.scanner.oast.OastService oastService;

	public GraphqlInjectionScanner(ScanHttpClient httpClient,
			ch.nexsol.orthrusdast.scanner.payload.PayloadLoaderService payloadLoader,
			ch.nexsol.orthrusdast.scanner.payload.PayloadMutator payloadMutator,
			ch.nexsol.orthrusdast.scanner.oast.OastService oastService) {
		this.httpClient = httpClient;
		this.payloadLoader = payloadLoader;
		this.payloadMutator = payloadMutator;
		this.oastService = oastService;
	}

	@Override
	public String getId() {
		return "graphql-injection";
	}

	@Override
	public String getName() {
		return "GraphQL Injection Scanner";
	}

	@Override
	public Flux<Vulnerability> scan(Operation operation) {
		return Flux.defer(() -> {
			if (!org.springframework.http.HttpMethod.POST.equals(operation.method()) || operation.body() == null
					|| !operation.body().contains("\"variables\"")) {
				return Flux.empty();
			}

			return oastService.createSession().flatMapMany((oastSession) -> {
				try {
					Map<String, Object> bodyMap = objectMapper.readValue(operation.body(),
							new TypeReference<Map<String, Object>>() {
							});
					if (!bodyMap.containsKey("variables") || !(bodyMap.get("variables") instanceof Map)) {
						return Flux.empty();
					}

					@SuppressWarnings("unchecked")
					Map<String, Object> variables = (Map<String, Object>) bodyMap.get("variables");

					// Merge payloads from multiple categories
					Flux<String> allPayloads = Flux.concat(payloadLoader.getPayloads("sqli"),
							payloadLoader.getPayloads("cmd-injection"), payloadLoader.getPayloads("nosql"),
							payloadLoader.getPayloads("ssti"));

					Flux<Vulnerability> scanVulns = Flux.fromIterable(variables.keySet())
						.flatMap((varName) -> allPayloads.concatMap((rawPayload) -> {
							String oastPayload = rawPayload.replace("{{OAST_HOST}}", oastSession.domain());
							String payload = payloadMutator.mutate(oastPayload,
									ch.nexsol.orthrusdast.scanner.payload.PayloadMutator.Context.JSON_BODY);
							return testVariable(operation, bodyMap, variables, varName, payload);
						}));

					return scanVulns.concatWith(oastService.pollInteractions(oastSession)
						.map((interaction) -> createVulnerabilityWithTrace("Out-Of-Band (Blind) Injection in GraphQL",
								"The endpoint evaluated a payload and made an out-of-band request to the OAST server. This indicates a blind injection vulnerability (e.g. Blind SQLi, Blind CmdInj, SSRF).",
								RiskLevel.CRITICAL, Vulnerability.Confidence.HIGH, operation, CWEReference.CWE_89, // Defaulting
																													// to
																													// 89,
																													// though
																													// could
																													// be
																													// 78
																													// or
																													// SSRF
								List.of("CAPEC-66"), 9.8,
								"An interaction was received from " + interaction.remoteAddress() + " via "
										+ interaction.protocol(),
								"Validate and sanitize all GraphQL variable inputs.", operation, null,
								"API Endpoint (Network)", "Unauthorized Access / Data Exposure")));

				}
				catch (Exception ex) {
					log.warn("Failed to parse GraphQL body for injection scanning: {}", ex.getMessage());
					return Flux.empty();
				}
			});
		});
	}

	private Flux<Vulnerability> testVariable(Operation operation, Map<String, Object> originalBodyMap,
			Map<String, Object> originalVariables, String varName, String payload) {

		try {
			Map<String, Object> modifiedVariables = new HashMap<>(originalVariables);
			modifiedVariables.put(varName, payload);

			Map<String, Object> modifiedBodyMap = new HashMap<>(originalBodyMap);
			modifiedBodyMap.put("variables", modifiedVariables);

			String newBody = objectMapper.writeValueAsString(modifiedBodyMap);

			Operation testOp = new Operation(operation.url(), operation.method(), operation.headers(),
					operation.queryParams(), newBody, operation.securityRequirements(),
					operation.expectedContentTypes(), operation.authScheme());

			return httpClient.send(testOp).flatMapMany((response) -> {
				int status = response.statusCode().value();
				boolean isClientError = status >= 400 && status < 500;
				if (response.responseTimeMs() > 4000 && payload.contains("sleep") && status != 503 && status != 504
						&& !isClientError) {
					Vulnerability vuln = createVulnerabilityWithTrace("Time-Based Blind Injection in GraphQL Variable",
							"The endpoint might be vulnerable to Time-Based Blind Injection via the '" + varName
									+ "' variable.",
							RiskLevel.CRITICAL, Vulnerability.Confidence.HIGH, operation, CWEReference.CWE_89,
							List.of("CAPEC-66"), 9.8,
							"Response was delayed by " + response.responseTimeMs() + "ms when payload '" + payload
									+ "' was supplied.",
							"Validate and sanitize all GraphQL variable inputs. Use parameterized queries for databases.",
							testOp, response, "API Endpoint (Network)", "Unauthorized Access / Data Exposure");
					return Flux.just(vuln);
				}

				String body = response.body() != null ? response.body().toLowerCase() : "";
				boolean hasError = body.contains("syntax error") || body.contains("mysql_fetch")
						|| body.contains("ora-") || body.contains("command not found");

				if (hasError) {
					Vulnerability vuln = createVulnerabilityWithTrace("Potential Injection in GraphQL Variable",
							"The endpoint might be vulnerable to Injection via the '" + varName + "' variable.",
							RiskLevel.HIGH, Vulnerability.Confidence.MEDIUM, operation, CWEReference.CWE_89,
							List.of("CAPEC-66"), 9.8,
							"Response indicates a potential injection error when payload '" + payload
									+ "' was supplied.",
							"Validate and sanitize all GraphQL variable inputs. Use parameterized queries for databases.",
							testOp, response, "API Endpoint (Network)", "Unauthorized Access / Data Exposure");
					return Flux.just(vuln);
				}
				return Flux.empty();
			});
		}
		catch (Exception ex) {
			return Flux.empty();
		}
	}

	private String truncate(String text) {
		if (text == null) {
			return "null";
		}
		return (text.length() > 200) ? text.substring(0, 200) + "..." : text;
	}

}

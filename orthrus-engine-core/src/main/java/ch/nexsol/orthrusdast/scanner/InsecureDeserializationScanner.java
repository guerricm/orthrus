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
import java.util.Map;

import org.springframework.stereotype.Component;

import reactor.core.publisher.Flux;

import ch.nexsol.orthrusdast.http.ScanHttpClient;
import ch.nexsol.orthrusdast.model.CWEReference;
import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.RiskLevel;
import ch.nexsol.orthrusdast.model.Vulnerability;

import ch.nexsol.orthrusdast.scanner.oast.OastService;
import java.io.ObjectInputStream;
import java.lang.Class;
import java.net.URL;

/**
 * Scans for Insecure Deserialization vulnerabilities by sending known magic bytes or
 * serialized payloads.
 */
@Component
public class InsecureDeserializationScanner implements SecurityScanner {

	private final ScanHttpClient httpClient;

	private final OastService oastService;

	// Common magic payloads that cause predictable errors if deserialized
	private static final Map<String, String> PAYLOADS = Map.of("Java Serialized (Hex encoded header)", "rO0ABXNyAA...",
			"Python Pickle", "c__builtin__\neval\n(Vprint(1)\ntR.", "Jackson/Fastjson Gadget (Error-Based)",
			"{\"@type\":\"Class\",\"val\":\"com.sun.rowset.JdbcRowSetImpl\"}");

	public InsecureDeserializationScanner(ScanHttpClient httpClient, OastService oastService) {
		this.httpClient = httpClient;
		this.oastService = oastService;
	}

	@Override
	public String getId() {
		return "insecure-deserialization";
	}

	@Override
	public String getName() {
		return "Insecure Deserialization Scanner";
	}

	@Override
	public Flux<Vulnerability> scan(Operation operation) {
		return Flux.defer(() -> {
			if (!List.of("POST", "PUT", "PATCH").contains(operation.method().name())) {
				return Flux.empty();
			}

			return oastService.createSession().flatMapMany((oastSession) -> {

				// OAST Gadget Payload (Fastjson / Jackson DNS lookup)
				String oastGadget = "{\"@type\":\"URL\",\"val\":\"http://" + oastSession.domain() + "\"}";

				Operation oastOp = new Operation(operation.url(), operation.method(), operation.headers(),
						operation.queryParams(), oastGadget, operation.securityRequirements(),
						operation.expectedContentTypes(), operation.authScheme());

				Flux<Vulnerability> errorBasedVulns = Flux.fromIterable(PAYLOADS.entrySet()).flatMap((entry) -> {
					String payloadName = entry.getKey();
					String payload = entry.getValue();

					Operation testOp = new Operation(operation.url(), operation.method(), operation.headers(),
							operation.queryParams(), payload, operation.securityRequirements(),
							operation.expectedContentTypes(), operation.authScheme());

					return httpClient.send(testOp).flatMapMany((response) -> {
						// If the server returns a 500 or stack trace containing
						// deserialization errors, flag it
						if (response.statusCode().is5xxServerError() && (response.bodyContains("ObjectInputStream")
								|| response.bodyContains("ClassCastException") || response.bodyContains("cPickle")
								|| response.bodyContains("fastjson") || response.bodyContains("Jackson"))) {

							Vulnerability vuln = createVulnerabilityWithTrace("Insecure Deserialization",
									"The endpoint appears to blindly deserialize the request body. Sending a "
											+ payloadName + " payload triggered a deserialization error.",
									RiskLevel.CRITICAL, Vulnerability.Confidence.MEDIUM, operation,
									CWEReference.CWE_502, List.of("CAPEC-586"), 9.8,
									"Server responded with a stack trace indicating deserialization failure.",
									"Avoid deserializing untrusted data. If necessary, use safe formats like standard JSON, or use strict type whitelisting.",
									testOp, response, "API Endpoint (Network)", "Unauthorized Access / Data Exposure");
							return Flux.just(vuln);
						}
						return Flux.empty();
					});
				});

				Flux<Vulnerability> blindVulns = httpClient.send(oastOp)
					.flatMapMany((res) -> Flux.<Vulnerability>empty()) // We don't care
																		// about the
																		// response body
					.concatWith(oastService.pollInteractions(oastSession)
						.map((interaction) -> createVulnerabilityWithTrace("Blind Insecure Deserialization (OAST)",
								"The endpoint successfully deserialized a gadget payload (URL) and made an out-of-band request to the OAST server.",
								RiskLevel.CRITICAL, Vulnerability.Confidence.HIGH, operation, CWEReference.CWE_502,
								List.of("CAPEC-586"), 9.8,
								"An interaction was received from " + interaction.remoteAddress() + " via "
										+ interaction.protocol(),
								"Disable default typing in Jackson/Fastjson. Avoid deserializing untrusted data.",
								oastOp, null, "API Endpoint (Network)", "Unauthorized Access / Data Exposure")));

				return Flux.concat(errorBasedVulns, blindVulns);
			});
		});
	}

}

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
import ch.nexsol.orthrusdast.model.Vulnerability;

/**
 * Scans for Path Traversal / Directory Traversal vulnerabilities (CWE-22).
 */
@Component
public class PathTraversalScanner implements SecurityScanner {

	private static final Logger log = LoggerFactory.getLogger(PathTraversalScanner.class);

	private final ScanHttpClient httpClient;

	private static final String PAYLOAD = "../../../../../../../../../../../../etc/passwd";

	private static final String WINDOWS_PAYLOAD = "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini";

	public PathTraversalScanner(ScanHttpClient httpClient) {
		this.httpClient = httpClient;
	}

	@Override
	public String getId() {
		return "path-traversal";
	}

	@Override
	public String getName() {
		return "Path Traversal Scanner";
	}

	@Override
	public ScannerFamily getFamily() {
		return ScannerFamily.INJECTION;
	}

	@Override
	public Flux<Vulnerability> scan(Operation operation) {
		return Flux.defer(() -> {
			List<String> payloads = List.of("../../../../../../../../../../../../etc/passwd",
					"..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
					"%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
					"%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%2fpasswd",
					"../../../../../../../../../../../../etc/passwd%00.png");

			return Flux.fromIterable(payloads).concatMap((payload) -> {
				return InjectionHelper.generateInjectedOperations(operation, payload)
					.concatMap((test) -> httpClient.send(test.mutatedOperation()).flatMapMany((response) -> {
						boolean linuxVuln = response.bodyContains("root:x:0:0");
						boolean windowsVuln = response.bodyContains("[extensions]") || response.bodyContains("[fonts]");

						if (linuxVuln || windowsVuln) {
							Vulnerability vuln = createVulnerabilityWithTrace("Path Traversal (LFI)",
									"The endpoint allows an attacker to read arbitrary files on the server filesystem.",
									RiskLevel.CRITICAL, Vulnerability.Confidence.HIGH, operation, CWEReference.CWE_22,
									List.of("CAPEC-126"), 7.5,
									"Response contains contents of a sensitive OS file when injecting " + payload
											+ " into " + test.injectionPoint() + ".",
									"Validate input against an allowlist. Avoid passing raw user input to filesystem APIs. Use path canonicalization and verify the target path is within the expected directory.",
									test.mutatedOperation(), response, "API Endpoint (Network)",
									"Unauthorized Access / Data Exposure");
							return Flux.just(vuln);
						}
						return Flux.empty();
					}));
			});
		});
	}

}

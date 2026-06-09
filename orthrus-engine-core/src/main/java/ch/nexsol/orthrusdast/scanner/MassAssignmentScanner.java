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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import reactor.core.publisher.Flux;

import ch.nexsol.orthrusdast.http.ScanHttpClient;
import ch.nexsol.orthrusdast.model.CWEReference;
import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.RiskLevel;
import ch.nexsol.orthrusdast.model.Vulnerability;

/**
 * Scans for Mass Assignment / BOPLA (API3:2023) (CWE-915).
 */
@Component
public class MassAssignmentScanner implements SecurityScanner {

	private static final Logger log = LoggerFactory.getLogger(MassAssignmentScanner.class);

	private final ScanHttpClient httpClient;

	private final ObjectMapper mapper = new ObjectMapper();

	public MassAssignmentScanner(ScanHttpClient httpClient) {
		this.httpClient = httpClient;
	}

	@Override
	public String getId() {
		return "mass-assignment";
	}

	@Override
	public String getName() {
		return "Mass Assignment Scanner (BOPLA)";
	}

	@Override
	public Flux<Vulnerability> scan(Operation operation) {
		return Flux.defer(() -> {
			String method = operation.method().toUpperCase();
			if (!("POST".equals(method) || "PUT".equals(method) || "PATCH".equals(method))) {
				return Flux.empty();
			}

			if (operation.body() == null || operation.body().isEmpty() || !operation.body().trim().startsWith("{")) {
				return Flux.empty();
			}

			try {
				ObjectNode jsonBody = (ObjectNode) mapper.readTree(operation.body());

				// Define sensitive fields to inject
				String[] sensitiveBooleanFields = { "is_admin", "isAdmin", "deleted", "is_deleted", "isOwner", "system",
						"superuser" };
				String[] sensitiveStringFields = { "role", "permissions", "group", "status", "privilege",
						"account_type", "user_type" };
				String[] sensitiveIntFields = { "user_id", "tenant_id", "account_id", "org_id", "balance", "credit" };

				// Test 1: Standard Injection (Booleans, Strings, Ints)
				ObjectNode standardInject = jsonBody.deepCopy();
				for (String field : sensitiveBooleanFields)
					standardInject.put(field, true);
				for (String field : sensitiveStringFields)
					standardInject.put(field, "admin");
				for (String field : sensitiveIntFields)
					standardInject.put(field, 1);
				String standardBody = mapper.writeValueAsString(standardInject);

				// Test 2: Type Confusion (Arrays and Objects)
				ObjectNode typeConfusionInject = jsonBody.deepCopy();
				for (String field : sensitiveBooleanFields)
					typeConfusionInject.putArray(field).add(true);
				for (String field : sensitiveStringFields)
					typeConfusionInject.putObject(field).put("id", 1);
				String typeConfusionBody = mapper.writeValueAsString(typeConfusionInject);

				Operation standardOp = new Operation(operation.url(), operation.method(), operation.headers(),
						operation.queryParams(), standardBody, operation.securityRequirements(),
						operation.expectedContentTypes(), operation.authScheme());

				Operation typeConfusionOp = new Operation(operation.url(), operation.method(), operation.headers(),
						operation.queryParams(), typeConfusionBody, operation.securityRequirements(),
						operation.expectedContentTypes(), operation.authScheme());

				return Flux.concat(
						executeMassAssignmentCheck(standardOp, operation, "Standard Injection",
								"injected sensitive fields (booleans, strings, ints)"),
						executeMassAssignmentCheck(typeConfusionOp, operation, "Type Confusion Injection",
								"injected sensitive fields using unexpected types (Arrays, Objects)"));

			}
			catch (Exception ex) {
				log.debug("Failed to parse or modify JSON body for {}: {}", operation.url(), ex.getMessage());
				return Flux.empty();
			}
		});
	}

	private Flux<Vulnerability> executeMassAssignmentCheck(Operation testOp, Operation originalOp, String testType,
			String context) {
		return httpClient.send(testOp).flatMapMany((response) -> {
			// If the server accepts the modified payload without a 400 Bad Request, it
			// MIGHT be vulnerable
			if (response.isSuccessful() && !response.bodyContains("invalid type")
					&& !response.bodyContains("validation error")) {
				Vulnerability vuln = createVulnerabilityWithTrace("Potential Mass Assignment (BOPLA) - " + testType,
						"The endpoint accepts unexpected fields in the JSON payload without returning a validation error.",
						RiskLevel.MEDIUM, Vulnerability.Confidence.LOW, originalOp, CWEReference.CWE_915,
						List.of("CAPEC-17"), 6.5,
						"Server returned " + response.statusCode() + " OK after " + context + " into the JSON payload.",
						"Use DTOs (Data Transfer Objects) to explicitly map accepted fields. Avoid binding HTTP requests directly to domain models or database entities. Enforce strict JSON schema validation.",
						testOp, response, "API Endpoint (Network)", "Unauthorized Access / Data Exposure");
				return Flux.just(vuln);
			}
			return Flux.empty();
		});
	}

}

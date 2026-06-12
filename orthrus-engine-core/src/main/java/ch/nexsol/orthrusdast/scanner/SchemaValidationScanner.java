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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.stereotype.Component;

import tools.jackson.databind.ObjectMapper;

import reactor.core.publisher.Flux;

import ch.nexsol.orthrusdast.http.ScanHttpClient;
import ch.nexsol.orthrusdast.model.CWEReference;
import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.RiskLevel;
import ch.nexsol.orthrusdast.model.Vulnerability;

import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.parameters.Parameter;

/**
 * Scans for Improper Input Validation (CWE-20) by testing OpenAPI schema constraints. It
 * verifies if the API actually enforces required fields, max lengths, bounds, enums,
 * patterns, arrays limits, and data types across both the Request Body and Parameters.
 */
@Component
@SuppressWarnings({ "rawtypes", "unchecked" })
public class SchemaValidationScanner implements SecurityScanner {

	private final ScanHttpClient httpClient;

	private final ObjectMapper objectMapper = new ObjectMapper();

	public SchemaValidationScanner(ScanHttpClient httpClient) {
		this.httpClient = httpClient;
	}

	@Override
	public String getId() {
		return "schema-validation";
	}

	@Override
	public String getName() {
		return "Schema Validation Scanner";
	}

	@Override
	public ScannerFamily getFamily() {
		return ScannerFamily.LOGIC;
	}

	@Override
	public Flux<Vulnerability> scan(Operation operation) {
		return Flux.defer(() -> {
			if (!(operation.sourceNode() instanceof io.swagger.v3.oas.models.Operation openApiOperation)) {
				return Flux.empty();
			}

			List<Flux<Vulnerability>> allScans = new ArrayList<>();

			// 1. Request Body Validation
			if (List.of("POST", "PUT", "PATCH").contains(operation.method().name())) {
				if (openApiOperation.getRequestBody() != null
						&& openApiOperation.getRequestBody().getContent() != null) {
					io.swagger.v3.oas.models.media.MediaType mediaType = openApiOperation.getRequestBody()
						.getContent()
						.get("application/json");
					if (mediaType != null && mediaType.getSchema() != null) {
						allScans.addAll(generateRequestBodyTests(operation, mediaType.getSchema()));
					}
				}
			}

			// 2. Parameters Validation (Query / Header)
			if (openApiOperation.getParameters() != null) {
				allScans.addAll(generateParameterTests(operation, openApiOperation.getParameters()));
			}

			return Flux.merge(allScans);
		});
	}

	private List<Flux<Vulnerability>> generateRequestBodyTests(Operation operation, Schema schema) {
		List<Flux<Vulnerability>> scans = new ArrayList<>();
		if (schema.getProperties() == null) {
			return scans;
		}

		Map<String, Object> baseline = buildBaseline(schema);
		Map<String, Schema> properties = schema.getProperties();

		// Check additionalProperties: false
		if (schema.getAdditionalProperties() instanceof Boolean && !((Boolean) schema.getAdditionalProperties())) {
			Map<String, Object> mutated = new HashMap<>(baseline);
			mutated.put("orthrus_injected_unknown_field", "test_value");
			scans.add(testBodyPayload(operation, mutated, "Additional Properties Violation",
					"The schema defines additionalProperties: false, but providing an undocumented field did not result in a 400 Bad Request error."));
		}

		for (Map.Entry<String, Schema> entry : properties.entrySet()) {
			String propName = entry.getKey();
			Schema propSchema = entry.getValue();

			// Test 1: Missing required property
			if (schema.getRequired() != null && schema.getRequired().contains(propName)) {
				Map<String, Object> mutated = new HashMap<>(baseline);
				mutated.remove(propName);
				scans.add(testBodyPayload(operation, mutated, "Missing Required Property", "The property '" + propName
						+ "' is required by the OpenAPI schema, but omitting it did not result in a 400 Bad Request error."));
			}

			// Constraints for Strings
			if ("string".equals(propSchema.getType())) {
				// Max Length
				if (propSchema.getMaxLength() != null) {
					Map<String, Object> mutated = new HashMap<>(baseline);
					mutated.put(propName, "A".repeat(propSchema.getMaxLength() + 10));
					scans.add(testBodyPayload(operation, mutated, "Max Length Violation",
							"The property '" + propName + "' has a maxLength of " + propSchema.getMaxLength()
									+ ", but providing a longer string was accepted."));
				}
				else {
					// Unbounded string test (Massive payload to test for memory
					// exhaustion / DoS)
					Map<String, Object> mutated = new HashMap<>(baseline);
					mutated.put(propName, "A".repeat(50_000)); // 50 KB payload
					scans.add(testBodyPayload(operation, mutated, "Missing Max Length (Unbounded String DoS)",
							"The property '" + propName
									+ "' lacks a maxLength constraint. An abnormally large string (50 KB) was sent and caused a 2xx or 5xx response, indicating missing bounds checking and potential DoS vulnerability."));
				}
				// Min Length
				if (propSchema.getMinLength() != null && propSchema.getMinLength() > 0) {
					Map<String, Object> mutated = new HashMap<>(baseline);
					mutated.put(propName, "A".repeat(Math.max(0, propSchema.getMinLength() - 1)));
					scans.add(testBodyPayload(operation, mutated, "Min Length Violation",
							"The property '" + propName + "' has a minLength of " + propSchema.getMinLength()
									+ ", but providing a shorter string was accepted."));
				}
				// Pattern
				if (propSchema.getPattern() != null) {
					Map<String, Object> mutated = new HashMap<>(baseline);
					mutated.put(propName, "invalid_pattern_string_!@#$%^&*()");
					scans.add(testBodyPayload(operation, mutated, "Pattern Constraint Violation", "The property '"
							+ propName + "' expects a specific regex pattern, but an invalid string was accepted."));
				}
				// Enum
				if (propSchema.getEnum() != null && !propSchema.getEnum().isEmpty()) {
					Map<String, Object> mutated = new HashMap<>(baseline);
					mutated.put(propName, "ORTHRUS_INVALID_ENUM_VALUE");
					scans.add(testBodyPayload(operation, mutated, "Enum Constraint Violation", "The property '"
							+ propName + "' defines an enum, but a value outside the allowed list was accepted."));
				}
				// Format
				if (propSchema.getFormat() != null) {
					Map<String, Object> mutated = new HashMap<>(baseline);
					if ("email".equals(propSchema.getFormat())) {
						mutated.put(propName, "not-an-email-address");
					}
					else if ("uuid".equals(propSchema.getFormat())) {
						mutated.put(propName, "not-a-uuid-1234");
					}
					else if ("date".equals(propSchema.getFormat())) {
						mutated.put(propName, "2024-13-45");
					}
					scans.add(testBodyPayload(operation, mutated, "Format Constraint Violation",
							"The property '" + propName + "' expects format '" + propSchema.getFormat()
									+ "', but an invalid format was accepted."));
				}
			}

			// Constraints for Numbers
			if ("integer".equals(propSchema.getType()) || "number".equals(propSchema.getType())) {
				// Type mismatch
				Map<String, Object> mutatedType = new HashMap<>(baseline);
				mutatedType.put(propName, "invalid_string_instead_of_number");
				scans.add(testBodyPayload(operation, mutatedType, "Type Constraint Violation",
						"The property '" + propName + "' expects a number, but providing a string was accepted."));

				// Maximum
				if (propSchema.getMaximum() != null) {
					Map<String, Object> mutated = new HashMap<>(baseline);
					mutated.put(propName, propSchema.getMaximum().longValue() + 10);
					scans.add(testBodyPayload(operation, mutated, "Maximum Constraint Violation",
							"The property '" + propName + "' has a maximum of " + propSchema.getMaximum()
									+ ", but a larger value was accepted."));
				}
				// Minimum
				if (propSchema.getMinimum() != null) {
					Map<String, Object> mutated = new HashMap<>(baseline);
					mutated.put(propName, propSchema.getMinimum().longValue() - 10);
					scans.add(testBodyPayload(operation, mutated, "Minimum Constraint Violation",
							"The property '" + propName + "' has a minimum of " + propSchema.getMinimum()
									+ ", but a smaller value was accepted."));
				}
			}

			// Constraints for Arrays
			if ("array".equals(propSchema.getType())) {
				if (propSchema.getMaxItems() != null) {
					Map<String, Object> mutated = new HashMap<>(baseline);
					List<String> list = new ArrayList<>();
					for (int i = 0; i <= propSchema.getMaxItems(); i++)
						list.add("item");
					mutated.put(propName, list);
					scans.add(testBodyPayload(operation, mutated, "Max Items Constraint Violation",
							"The array property '" + propName + "' has maxItems " + propSchema.getMaxItems()
									+ ", but a larger array was accepted."));
				}
				if (propSchema.getMinItems() != null && propSchema.getMinItems() > 0) {
					Map<String, Object> mutated = new HashMap<>(baseline);
					List<String> list = new ArrayList<>();
					for (int i = 0; i < propSchema.getMinItems() - 1; i++)
						list.add("item");
					mutated.put(propName, list);
					scans.add(testBodyPayload(operation, mutated, "Min Items Constraint Violation",
							"The array property '" + propName + "' has minItems " + propSchema.getMinItems()
									+ ", but a smaller array was accepted."));
				}
			}
		}
		return scans;
	}

	private List<Flux<Vulnerability>> generateParameterTests(Operation baseOp, List<Parameter> parameters) {
		List<Flux<Vulnerability>> scans = new ArrayList<>();

		for (Parameter param : parameters) {
			if (param.getSchema() == null) {
				continue;
			}

			String pName = param.getName();
			Schema pSchema = param.getSchema();

			// Missing Required Parameter (Only for Query and Header, Path is implicitly
			// required by URL)
			if (Boolean.TRUE.equals(param.getRequired())
					&& ("query".equals(param.getIn()) || "header".equals(param.getIn()))) {
				Operation mutatedOp = removeParameter(baseOp, param.getIn(), pName);
				scans.add(testOperation(mutatedOp, "Missing Required Parameter",
						"The parameter '" + pName + "' is required in " + param.getIn()
								+ " but was omitted, and the server did not return 400."));
			}

			// Constraints for String Parameters
			if ("string".equals(pSchema.getType())) {
				if (pSchema.getMaxLength() != null) {
					scans.add(
							testOperation(
									mutateParameter(baseOp, param.getIn(), pName,
											"A".repeat(pSchema.getMaxLength() + 10)),
									"Parameter Max Length Violation",
									"Parameter '" + pName + "' exceeded maxLength but was accepted."));
				}
				else {
					scans.add(testOperation(mutateParameter(baseOp, param.getIn(), pName, "A"
						.repeat(50_000)), "Missing Parameter Max Length (Unbounded)", "Parameter '" + pName
								+ "' lacks a maxLength constraint. An abnormally large string (50 KB) was accepted, potential DoS."));
				}
				if (pSchema.getEnum() != null && !pSchema.getEnum().isEmpty()) {
					scans.add(testOperation(mutateParameter(baseOp, param.getIn(), pName, "ORTHRUS_INVALID_ENUM"),
							"Parameter Enum Violation",
							"Parameter '" + pName + "' received an invalid enum value but was accepted."));
				}
			}

			// Constraints for Number Parameters
			if ("integer".equals(pSchema.getType()) || "number".equals(pSchema.getType())) {
				scans.add(testOperation(mutateParameter(baseOp, param.getIn(), pName, "invalid_string_not_number"),
						"Parameter Type Violation",
						"Parameter '" + pName + "' expects a number but accepted a string."));

				if (pSchema.getMaximum() != null) {
					scans.add(testOperation(
							mutateParameter(baseOp, param.getIn(), pName,
									String.valueOf(pSchema.getMaximum().longValue() + 10)),
							"Parameter Maximum Violation",
							"Parameter '" + pName + "' exceeded maximum but was accepted."));
				}
				if (pSchema.getMinimum() != null) {
					scans.add(testOperation(
							mutateParameter(baseOp, param.getIn(), pName,
									String.valueOf(pSchema.getMinimum().longValue() - 10)),
							"Parameter Minimum Violation",
							"Parameter '" + pName + "' was below minimum but was accepted."));
				}
			}
		}

		return scans;
	}

	private Operation removeParameter(Operation op, String in, String name) {
		Map<String, String> newQuery = op.queryParams() != null ? new HashMap<>(op.queryParams()) : new HashMap<>();
		Map<String, String> newHeaders = op.headers() != null ? new HashMap<>(op.headers()) : new HashMap<>();

		if ("query".equals(in)) {
			newQuery.remove(name);
		}
		if ("header".equals(in)) {
			newHeaders.remove(name);
		}

		return new Operation(op.url(), op.method(), newHeaders, newQuery, op.body(), op.securityRequirements(),
				op.expectedContentTypes(), op.authScheme(), op.templateUrl(), op.sourceNode());
	}

	private Operation mutateParameter(Operation op, String in, String name, String value) {
		Map<String, String> newQuery = op.queryParams() != null ? new HashMap<>(op.queryParams()) : new HashMap<>();
		Map<String, String> newHeaders = op.headers() != null ? new HashMap<>(op.headers()) : new HashMap<>();
		String newUrl = op.url();

		if ("query".equals(in)) {
			newQuery.put(name, value);
		}
		if ("header".equals(in)) {
			newHeaders.put(name, value);
		}
		if ("path".equals(in)) {
			newUrl = mutatePathParameter(op.url(), op.templateUrl(), name, value);
		}

		return new Operation(newUrl, op.method(), newHeaders, newQuery, op.body(), op.securityRequirements(),
				op.expectedContentTypes(), op.authScheme(), op.templateUrl(), op.sourceNode());
	}

	private String mutatePathParameter(String url, String templateUrl, String paramName, String newValue) {
		if (url == null || templateUrl == null) {
			return url;
		}

		String[] urlParts = url.split("/");
		String[] templateParts = templateUrl.split("/");

		if (urlParts.length != templateParts.length) {
			// Fallback if structure mismatches
			return url.replace(url.substring(url.lastIndexOf('/') + 1), newValue);
		}

		String target = "{" + paramName + "}";
		for (int i = 0; i < templateParts.length; i++) {
			if (templateParts[i].contains(target)) {
				urlParts[i] = templateParts[i].replace(target, newValue);
			}
		}
		return String.join("/", urlParts);
	}

	private Map<String, Object> buildBaseline(Schema schema) {
		Map<String, Object> result = new HashMap<>();
		Map<String, Schema> properties = schema.getProperties();
		if (properties != null) {
			for (Map.Entry<String, Schema> entry : properties.entrySet()) {
				result.put(entry.getKey(), getDummyValue(entry.getValue()));
			}
		}
		return result;
	}

	private Object getDummyValue(Schema propSchema) {
		if ("integer".equals(propSchema.getType()) || "number".equals(propSchema.getType())) {
			return 42;
		}
		else if ("boolean".equals(propSchema.getType())) {
			return true;
		}
		else if ("array".equals(propSchema.getType())) {
			return List.of("test");
		}
		return "valid_string";
	}

	private Flux<Vulnerability> testBodyPayload(Operation operation, Map<String, Object> payloadMap, String testName,
			String description) {
		String payloadJson;
		try {
			payloadJson = objectMapper.writeValueAsString(payloadMap);
		}
		catch (Exception ex) {
			return Flux.empty();
		}

		Operation testOp = new Operation(operation.url(), operation.method(), operation.headers(),
				operation.queryParams(), payloadJson, operation.securityRequirements(),
				operation.expectedContentTypes(), operation.authScheme(), operation.templateUrl(),
				operation.sourceNode());

		return testOperation(testOp, testName, description);
	}

	private Flux<Vulnerability> testOperation(Operation testOp, String testName, String description) {
		return httpClient.send(testOp).flatMapMany((response) -> {
			List<Vulnerability> vulns = new ArrayList<>();

			// A well-implemented API should return 4xx (Client Error) for schema
			// violations.
			// If it returns 2xx (Success) or 500 (Server Crash), it indicates improper
			// input validation.
			// We ignore 502/503/504 as they are usually API Gateway/Load Balancer
			// responses.
			boolean isAppCrash = response.statusCode().is5xxServerError() && response.statusCode().value() != 502
					&& response.statusCode().value() != 503 && response.statusCode().value() != 504;

			if (response.statusCode().is2xxSuccessful() || isAppCrash) {
				Vulnerability vuln = createVulnerabilityWithTrace("Improper Input Validation (" + testName + ")",
						description, RiskLevel.MEDIUM, Vulnerability.Confidence.HIGH, testOp, CWEReference.CWE_20,
						List.of("CAPEC-3"), 5.3,
						"The server responded with " + response.statusCode()
								+ " instead of enforcing the schema constraint (should be 400).",
						"Ensure that all incoming data is strictly validated against the defined OpenAPI schema constraints (types, lengths, required fields) using a validation middleware before processing.",
						testOp, response, "API Endpoint (Network)", "Unauthorized Access / Data Exposure");
				vulns.add(vuln);
			}

			if (response.statusCode().value() != 401 && response.statusCode().value() != 403) {
				String actualContentType = response.getHeader("Content-Type");
				if (actualContentType != null && testOp.expectedContentTypes() != null
						&& !testOp.expectedContentTypes().isEmpty()) {
					boolean match = testOp.expectedContentTypes()
						.stream()
						.anyMatch((expected) -> actualContentType.toLowerCase().contains(expected.toLowerCase()));
					if (!match) {
						vulns.add(createVulnerabilityWithTrace("Unexpected Content-Type (" + testName + ")",
								"The API responded with an undocumented Content-Type ('" + actualContentType
										+ "') instead of the expected format(s): " + testOp.expectedContentTypes()
										+ ". This often indicates an unhandled exception or bypass of the framework's standard error handler.",
								RiskLevel.LOW, Vulnerability.Confidence.HIGH, testOp, CWEReference.CWE_20,
								List.of("CAPEC-3"), 3.7, "Response Content-Type is: " + actualContentType,
								"Ensure that all API responses, including error messages (4xx/5xx), conform to the expected Content-Type (e.g., application/json). Check exception handlers to avoid returning raw text.",
								testOp, response, "API Endpoint (Network)", "Unauthorized Access / Data Exposure"));
					}
				}
			}

			return Flux.fromIterable(vulns);
		});
	}

}

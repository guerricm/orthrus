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

import ch.nexsol.orthrusdast.http.ScanHttpClient;
import ch.nexsol.orthrusdast.model.CWEReference;
import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.RiskLevel;
import ch.nexsol.orthrusdast.model.Vulnerability;
import ch.nexsol.orthrusdast.scanner.payload.PayloadLoaderService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Scanner for detecting Excessive Data Exposure (CWE-201 / CWE-213).
 */
@Component
public class ExcessiveDataExposureScanner implements SecurityScanner {

	private static final Logger log = LoggerFactory.getLogger(ExcessiveDataExposureScanner.class);

	private final ScanHttpClient httpClient;

	private final PayloadLoaderService payloadLoaderService;

	private final ObjectMapper objectMapper;

	private static final Pattern EMAIL_PATTERN = Pattern.compile("^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,6}$");

	private static final Pattern SSN_PATTERN = Pattern.compile("^(?!000|666)[0-8]\\d{2}-(?!00)\\d{2}-(?!0000)\\d{4}$");

	private static final Pattern AVS_PATTERN = Pattern.compile("^756\\.\\d{4}\\.\\d{4}\\.\\d{2}$");

	private static final Pattern CREDIT_CARD_PATTERN = Pattern
		.compile("^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})$");

	private static final Pattern JWT_PATTERN = Pattern.compile("^[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]*$");

	public ExcessiveDataExposureScanner(ScanHttpClient httpClient, PayloadLoaderService payloadLoaderService,
			ObjectMapper objectMapper) {
		this.httpClient = httpClient;
		this.payloadLoaderService = payloadLoaderService;
		this.objectMapper = objectMapper;
	}

	@Override
	public String getId() {
		return "excessive-data-exposure";
	}

	@Override
	public String getName() {
		return "Excessive Data Exposure Scanner";
	}

	@Override
	public ScannerFamily getFamily() {
		return ScannerFamily.LOGIC;
	}

	@Override
	public Flux<Vulnerability> scan(Operation operation) {
		if (operation.method().name().equals("OPTIONS") || operation.method().name().equals("HEAD")) {
			return Flux.empty();
		}

		return payloadLoaderService.getPayloads("sensitive-keys").collectList().flatMapMany((sensitiveKeys) -> {
			return httpClient.send(operation).flatMapMany((response) -> {

				if (!response.isSuccessful()) {
					return Flux.empty();
				}

				String contentType = response.headers().getFirst("Content-Type");
				if (contentType == null || (!contentType.toLowerCase().contains("application/json")
						&& !contentType.toLowerCase().contains("application/xml"))) {
					return Flux.empty();
				}

				String body = response.body();
				if (body == null || body.isEmpty()) {
					return Flux.empty();
				}

				List<String> findings = new ArrayList<>();

				if (contentType.toLowerCase().contains("application/json")) {
					try {
						JsonNode root = objectMapper.readTree(body);
						checkNode(root, sensitiveKeys, findings, "");
					}
					catch (JsonProcessingException e) {
						log.debug("Failed to parse JSON response for {}", operation.url());
					}
				}

				if (!findings.isEmpty()) {
					StringBuilder evidence = new StringBuilder(
							"Found the following sensitive data attributes in the response:\n");
					for (String finding : findings) {
						evidence.append("- ").append(finding).append("\n");
					}

					String description = "The endpoint returns sensitive data that might be excessive. "
							+ "If this API is consumed by a client that doesn't need all these details, it violates the principle of least privilege. "
							+ "\n\n⚠️ **FALSE POSITIVES LIKELY: Manual validation required.** "
							+ "If this is an internal API designed to return full records (e.g., admin panel), this may be legitimate. "
							+ "However, if this is an external-facing API, ensure you implement Data Masking or use strict DTOs.";

					String remediation = "Review the exposed fields. If the client application does not need this data to function, "
							+ "remove the fields from the response using dedicated Data Transfer Objects (DTOs) or apply Data Masking.";

					Vulnerability vuln = createVulnerabilityWithTrace("Excessive Data Exposure", description,
							RiskLevel.HIGH, Vulnerability.Confidence.MEDIUM, operation, CWEReference.CWE_201,
							List.of("CAPEC-118"), 6.5, evidence.toString(), remediation, operation, response,
							"API Endpoint (Network)", "Unauthorized Access / Data Exposure");

					return Flux.just(vuln);
				}

				return Flux.empty();
			});
		});
	}

	private void checkNode(JsonNode node, List<String> sensitiveKeys, List<String> findings, String path) {
		if (node.isObject()) {
			Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
			while (fields.hasNext()) {
				Map.Entry<String, JsonNode> field = fields.next();
				String keyName = field.getKey();
				JsonNode valueNode = field.getValue();

				String currentPath = path.isEmpty() ? keyName : path + "." + keyName;

				for (String sKey : sensitiveKeys) {
					if (keyName.toLowerCase().contains(sKey.toLowerCase()) || keyName.equalsIgnoreCase(sKey)) {
						if (valueNode.isValueNode() && !valueNode.isNull() && !valueNode.asText().isEmpty()) {
							String valStr = valueNode.asText();
							if (isActuallySensitive(sKey, valStr)) {
								findings.add("Field: '" + currentPath + "', Value: '" + valStr + "' (Matched keyword: "
										+ sKey + ")");
								break;
							}
						}
					}
				}

				checkNode(valueNode, sensitiveKeys, findings, currentPath);
			}
		}
		else if (node.isArray()) {
			for (int i = 0; i < node.size(); i++) {
				checkNode(node.get(i), sensitiveKeys, findings, path + "[" + i + "]");
			}
		}
	}

	private boolean isActuallySensitive(String matchedKey, String value) {
		matchedKey = matchedKey.toLowerCase();
		if (matchedKey.contains("email") || matchedKey.contains("mail")) {
			return EMAIL_PATTERN.matcher(value).matches();
		}
		if (matchedKey.contains("ssn") || matchedKey.contains("secu")) {
			return SSN_PATTERN.matcher(value).matches() || value.matches(".*\\d{13,15}.*");
		}
		if (matchedKey.contains("avs")) {
			return AVS_PATTERN.matcher(value).matches() || value.matches("^756.*");
		}
		if (matchedKey.contains("card") || matchedKey.contains("pan") || matchedKey.contains("cc_number")) {
			String clean = value.replaceAll("[\\s-]", "");
			return CREDIT_CARD_PATTERN.matcher(clean).matches();
		}
		if (matchedKey.contains("token") || matchedKey.contains("bearer")) {
			return JWT_PATTERN.matcher(value).matches() || value.length() > 20;
		}
		if (value.length() < 3) {
			return false;
		}
		if (value.equalsIgnoreCase("true") || value.equalsIgnoreCase("false") || value.equalsIgnoreCase("null")) {
			return false;
		}

		return true;
	}

}

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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import reactor.core.publisher.Flux;

import ch.nexsol.orthrusdast.model.Operation;

/**
 * Utility class to assist with injecting payloads into Operations. Generates test
 * operations by injecting a payload into: 1. Query parameters 2. High-risk HTTP headers
 * 3. JSON Body properties
 */
public class InjectionHelper {

	private static final ObjectMapper mapper = new ObjectMapper();

	private static final List<String> RISK_HEADERS = List.of("User-Agent", "Referer", "X-Forwarded-For",
			"Authorization");

	public static Flux<InjectionTest> generateInjectedOperations(Operation baseOp, String payload) {
		List<InjectionTest> testOps = new ArrayList<>();

		// 1. Query Params
		if (baseOp.queryParams() != null) {
			for (String param : baseOp.queryParams().keySet()) {
				Map<String, String> newParams = new HashMap<>(baseOp.queryParams());
				newParams.put(param, payload);
				testOps.add(
						new InjectionTest(
								new Operation(baseOp.url(), baseOp.method(), baseOp.headers(), newParams, baseOp.body(),
										baseOp.securityRequirements(), baseOp.expectedContentTypes(),
										baseOp.authScheme(), baseOp.templateUrl(), baseOp.sourceNode()),
								"Query Parameter '" + param + "'"));
			}
		}

		// 2. Headers (Focus on common injection headers)
		Map<String, String> baseHeaders = baseOp.headers() != null ? baseOp.headers() : new HashMap<>();
		for (String header : RISK_HEADERS) {
			Map<String, String> newHeaders = new HashMap<>(baseHeaders);
			newHeaders.put(header, payload);
			testOps.add(new InjectionTest(new Operation(baseOp.url(), baseOp.method(), newHeaders, baseOp.queryParams(),
					baseOp.body(), baseOp.securityRequirements(), baseOp.expectedContentTypes(), baseOp.authScheme(),
					baseOp.templateUrl(), baseOp.sourceNode()), "HTTP Header '" + header + "'"));
		}

		// 3. JSON Body
		if (baseOp.body() != null && baseOp.body().trim().startsWith("{")) {
			try {
				JsonNode rootNode = mapper.readTree(baseOp.body());
				if (rootNode.isObject()) {
					List<String> fieldNames = new ArrayList<>();
					rootNode.fieldNames().forEachRemaining(fieldNames::add);
					for (String field : fieldNames) {
						ObjectNode clonedNode = ((ObjectNode) rootNode).deepCopy();
						clonedNode.put(field, payload);
						testOps.add(new InjectionTest(new Operation(baseOp.url(), baseOp.method(), baseOp.headers(),
								baseOp.queryParams(), mapper.writeValueAsString(clonedNode),
								baseOp.securityRequirements(), baseOp.expectedContentTypes(), baseOp.authScheme(),
								baseOp.templateUrl(), baseOp.sourceNode()), "JSON Body Field '" + field + "'"));
					}
				}
			}
			catch (Exception ex) {
				// Ignore body parsing errors
			}
		}

		return Flux.fromIterable(testOps);
	}

	public record InjectionTest(Operation mutatedOperation, String injectionPoint) {
	}

}

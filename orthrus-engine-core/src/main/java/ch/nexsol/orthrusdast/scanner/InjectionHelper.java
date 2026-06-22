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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;

import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.scanner.payload.PayloadMutator;

/**
 * Utility class to assist with injecting payloads into Operations. Generates test
 * operations by injecting a payload into: 1. Query parameters 2. High-risk HTTP headers
 * 3. JSON body properties (both as a safe value and as a raw structural breakout) 4. XML
 * body text nodes.
 */
public final class InjectionHelper {

	private InjectionHelper() {
		// Private constructor for utility class
	}

	private static final ObjectMapper mapper = new ObjectMapper();

	private static final PayloadMutator MUTATOR = new PayloadMutator();

	// Placeholder used to splice a raw, unescaped payload into an otherwise
	// well-formed JSON document for structural breakout testing.
	private static final String RAW_PLACEHOLDER = "__ORTHRUS_RAW_PLACEHOLDER__";

	// Matches XML text nodes (the content between an opening and a closing tag).
	private static final Pattern XML_TEXT_NODE = Pattern.compile(">([^<>]+)<");

	// The Authorization header is intentionally excluded: overwriting it would drop the
	// authenticated session, yielding 401s that mask real findings (false negatives).
	private static final List<String> RISK_HEADERS = List.of("User-Agent", "Referer", "X-Forwarded-For");

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
		Map<String, String> baseHeaders = (baseOp.headers() != null) ? baseOp.headers() : new HashMap<>();
		for (String header : RISK_HEADERS) {
			Map<String, String> newHeaders = new HashMap<>(baseHeaders);
			newHeaders.put(header, payload);
			testOps.add(new InjectionTest(new Operation(baseOp.url(), baseOp.method(), newHeaders, baseOp.queryParams(),
					baseOp.body(), baseOp.securityRequirements(), baseOp.expectedContentTypes(), baseOp.authScheme(),
					baseOp.templateUrl(), baseOp.sourceNode()), "HTTP Header '" + header + "'"));
		}

		// 3. JSON Body
		Mono<List<InjectionTest>> jsonTestsMono = Mono.just(new ArrayList<>());
		if (baseOp.body() != null && baseOp.body().trim().startsWith("{")) {
			jsonTestsMono = Mono.fromCallable(() -> {
				List<InjectionTest> jsonTests = new ArrayList<>();
				JsonNode rootNode = mapper.readTree(baseOp.body());
				if (rootNode.isObject()) {
					for (String field : rootNode.propertyNames()) {
						ObjectNode clonedNode = ((ObjectNode) rootNode).deepCopy();
						clonedNode.put(field, payload);
						jsonTests.add(new InjectionTest(new Operation(baseOp.url(), baseOp.method(), baseOp.headers(),
								baseOp.queryParams(), mapper.writeValueAsString(clonedNode),
								baseOp.securityRequirements(), baseOp.expectedContentTypes(), baseOp.authScheme(),
								baseOp.templateUrl(), baseOp.sourceNode()), "JSON Body Field '" + field + "'"));

						String rawBody = buildRawBreakoutBody((ObjectNode) rootNode, field, payload);
						if (rawBody != null) {
							jsonTests.add(new InjectionTest(
									new Operation(baseOp.url(), baseOp.method(), baseOp.headers(), baseOp.queryParams(),
											rawBody, baseOp.securityRequirements(), baseOp.expectedContentTypes(),
											baseOp.authScheme(), baseOp.templateUrl(), baseOp.sourceNode()),
									"JSON Body Field '" + field + "' (raw breakout)"));
						}
					}
				}
				return jsonTests;
			}).onErrorReturn(new ArrayList<>());
		}

		return jsonTestsMono.flatMapMany((jsonTests) -> {
			testOps.addAll(jsonTests);

			// 4. XML Body (inject the payload, XML-escaped, into each text node)
			String body = (baseOp.body() != null) ? baseOp.body().trim() : "";
			if (body.startsWith("<") && !body.startsWith("<!") && !body.startsWith("<?xml-stylesheet")) {
				String escaped = MUTATOR.mutate(payload, PayloadMutator.Context.XML_BODY);
				Matcher matcher = XML_TEXT_NODE.matcher(baseOp.body());
				int nodeIndex = 0;
				while (matcher.find()) {
					nodeIndex++;
					String original = baseOp.body();
					String mutated = original.substring(0, matcher.start(1)) + escaped
							+ original.substring(matcher.end(1));
					testOps.add(new InjectionTest(
							new Operation(baseOp.url(), baseOp.method(), baseOp.headers(), baseOp.queryParams(),
									mutated, baseOp.securityRequirements(), baseOp.expectedContentTypes(),
									baseOp.authScheme(), baseOp.templateUrl(), baseOp.sourceNode()),
							"XML Body Text Node #" + nodeIndex));
				}
			}

			return Flux.fromIterable(testOps);
		});
	}

	/**
	 * Rebuilds a JSON document where the target field's value is the raw, unescaped
	 * payload, enabling structural breakout testing. Returns {@code null} if the document
	 * cannot be rebuilt safely.
	 * @param rootNode the parsed JSON object
	 * @param field the field whose value is replaced
	 * @param payload the raw payload to splice in
	 * @return the raw JSON body, or {@code null} on failure
	 */
	private static String buildRawBreakoutBody(ObjectNode rootNode, String field, String payload) throws Exception {
		ObjectNode clonedNode = rootNode.deepCopy();
		clonedNode.put(field, RAW_PLACEHOLDER);
		String serialized = mapper.writeValueAsString(clonedNode);
		String res = serialized.replace("\"" + RAW_PLACEHOLDER + "\"", "\"" + payload + "\"");
		return res.isEmpty() ? null : res;
	}

	public record InjectionTest(Operation mutatedOperation, String injectionPoint) {
	}

}

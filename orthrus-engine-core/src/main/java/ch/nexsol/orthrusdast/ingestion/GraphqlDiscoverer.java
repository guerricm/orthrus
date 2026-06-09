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

package ch.nexsol.orthrusdast.ingestion;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import reactor.core.publisher.Mono;

import ch.nexsol.orthrusdast.http.ScanHttpClient;
import ch.nexsol.orthrusdast.http.ScanHttpResponse;
import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.SecurityScheme;

@Component
public class GraphqlDiscoverer implements EndpointDiscoverer {

	private static final Logger log = LoggerFactory.getLogger(GraphqlDiscoverer.class);

	private final ScanHttpClient httpClient;

	private final ObjectMapper objectMapper = new ObjectMapper();

	private static final String INTROSPECTION_QUERY = "{\"query\": \"\\n    query IntrospectionQuery {\\n      __schema {\\n        queryType { name }\\n        mutationType { name }\\n        types {\\n          name\\n          kind\\n          fields {\\n            name\\n            args {\\n              name\\n              type {\\n                name\\n                kind\\n                ofType { name kind }\\n              }\\n            }\\n          }\\n        }\\n      }\\n    }\\n  \"}";

	public GraphqlDiscoverer(ScanHttpClient httpClient) {
		this.httpClient = httpClient;
	}

	@Override
	public String getId() {
		return "graphql";
	}

	@Override
	public Mono<List<Operation>> discover(String target, ch.nexsol.orthrusdast.model.ScanConfiguration config) {
		ch.nexsol.orthrusdast.model.SecurityScheme authScheme = config != null ? config.authScheme() : null;
		log.info("Starting GraphQL discovery on {}", target);

		Operation introspectionOp = new Operation(target, org.springframework.http.HttpMethod.POST,
				Map.of("Content-Type", "application/json", "Accept", "application/json"), Collections.emptyMap(),
				INTROSPECTION_QUERY, Collections.emptyList(), List.of("application/json"), authScheme);

		return httpClient.send(introspectionOp)
			.map((response) -> parseIntrospection(target, response, authScheme))
			.onErrorResume((e) -> {
				log.error("Failed to fetch GraphQL introspection from {}: {}", target, e.getMessage());
				return Mono.just(Collections.emptyList());
			});
	}

	private List<Operation> parseIntrospection(String targetUrl, ScanHttpResponse response, SecurityScheme authScheme) {
		List<Operation> operations = new ArrayList<>();
		if (response.statusCode().isError()) {
			log.warn("Introspection query failed with status {}", response.statusCode());
			return operations;
		}

		try {
			JsonNode root = objectMapper.readTree(response.body());
			JsonNode data = root.path("data").path("__schema");
			if (data.isMissingNode()) {
				log.warn("Invalid introspection response (no data.__schema found).");
				return operations;
			}

			String queryTypeName = data.path("queryType").path("name").asText("Query");
			String mutationTypeName = data.path("mutationType").path("name").asText("Mutation");

			JsonNode types = data.path("types");
			if (types.isArray()) {
				for (JsonNode typeNode : types) {
					String typeName = typeNode.path("name").asText();
					if (typeName.equals(queryTypeName) || typeName.equals(mutationTypeName)) {
						JsonNode fields = typeNode.path("fields");
						if (fields.isArray()) {
							for (JsonNode fieldNode : fields) {
								String fieldName = fieldNode.path("name").asText();
								String queryBody = buildDummyQuery(typeName.equals(mutationTypeName), fieldName,
										fieldNode.path("args"));

								Operation op = new Operation(targetUrl, org.springframework.http.HttpMethod.POST,
										Map.of("Content-Type", "application/json"), Collections.emptyMap(), queryBody,
										Collections.emptyList(), List.of("application/json"), authScheme);
								operations.add(op);
							}
						}
					}
				}
			}
			log.info("Discovered {} GraphQL operations.", operations.size());
		}
		catch (Exception ex) {
			log.error("Error parsing GraphQL introspection response", ex);
		}
		return operations;
	}

	private String buildDummyQuery(boolean isMutation, String fieldName, JsonNode argsNode) {
		StringBuilder queryBuilder = new StringBuilder();
		StringBuilder varsDefBuilder = new StringBuilder();
		StringBuilder varsCallBuilder = new StringBuilder();
		Map<String, Object> variablesMap = new java.util.HashMap<>();

		queryBuilder.append(isMutation ? "mutation" : "query");

		if (argsNode.isArray() && argsNode.size() > 0) {
			varsDefBuilder.append("(");
			varsCallBuilder.append("(");
			for (int i = 0; i < argsNode.size(); i++) {
				JsonNode arg = argsNode.get(i);
				String argName = arg.path("name").asText();
				String typeString = getGraphQLTypeString(arg.path("type"));

				varsDefBuilder.append("$").append(argName).append(": ").append(typeString);
				varsCallBuilder.append(argName).append(": $").append(argName);

				if (i < argsNode.size() - 1) {
					varsDefBuilder.append(", ");
					varsCallBuilder.append(", ");
				}

				variablesMap.put(argName, getDummyValueObjectForType(arg.path("type")));
			}
			varsDefBuilder.append(")");
			varsCallBuilder.append(")");
		}

		queryBuilder.append(varsDefBuilder.toString())
			.append(" { ")
			.append(fieldName)
			.append(varsCallBuilder.toString())
			.append(" { __typename } }");

		try {
			Map<String, Object> payload = new java.util.HashMap<>();
			payload.put("query", queryBuilder.toString());
			if (!variablesMap.isEmpty()) {
				payload.put("variables", variablesMap);
			}
			return objectMapper.writeValueAsString(payload);
		}
		catch (Exception ex) {
			return "{\"query\": \"{ " + fieldName + " }\"}";
		}
	}

	private String getGraphQLTypeString(JsonNode typeNode) {
		String kind = typeNode.path("kind").asText();
		if ("NON_NULL".equals(kind)) {
			return getGraphQLTypeString(typeNode.path("ofType")) + "!";
		}
		else if ("LIST".equals(kind)) {
			return "[" + getGraphQLTypeString(typeNode.path("ofType")) + "]";
		}
		return typeNode.path("name").asText("String");
	}

	private Object getDummyValueObjectForType(JsonNode typeNode) {
		String typeName = typeNode.path("name").asText(null);
		String kind = typeNode.path("kind").asText();

		if ("NON_NULL".equals(kind)) {
			return getDummyValueObjectForType(typeNode.path("ofType"));
		}
		else if ("LIST".equals(kind)) {
			return List.of(getDummyValueObjectForType(typeNode.path("ofType")));
		}

		if (typeName == null) {
			return "test";
		}

		return switch (typeName) {
			case "Int", "Float" -> 1;
			case "Boolean" -> true;
			case "ID" -> "1";
			default -> "test";
		};
	}

}

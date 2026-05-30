package ch.hug.vulnapi.ingestion;

import ch.hug.vulnapi.http.ScanHttpClient;
import ch.hug.vulnapi.http.ScanHttpResponse;
import ch.hug.vulnapi.model.Operation;
import ch.hug.vulnapi.model.SecurityScheme;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

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
    public Mono<List<Operation>> discover(String target, String overrideHost, SecurityScheme authScheme) {
        log.info("Starting GraphQL discovery on {}", target);

        Operation introspectionOp = new Operation(
                target,
                "POST",
                Map.of("Content-Type", "application/json", "Accept", "application/json"),
                Collections.emptyMap(),
                INTROSPECTION_QUERY,
                Collections.emptyList(),
                List.of("application/json"),
                authScheme);

        return httpClient.send(introspectionOp)
                .map(response -> parseIntrospection(target, response, authScheme))
                .onErrorResume(e -> {
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

                                Operation op = new Operation(
                                        targetUrl,
                                        "POST",
                                        Map.of("Content-Type", "application/json"),
                                        Collections.emptyMap(),
                                        queryBody,
                                        Collections.emptyList(),
                                        List.of("application/json"),
                                        authScheme);
                                operations.add(op);
                            }
                        }
                    }
                }
            }
            log.info("Discovered {} GraphQL operations.", operations.size());
        } catch (Exception e) {
            log.error("Error parsing GraphQL introspection response", e);
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

        queryBuilder.append(varsDefBuilder.toString()).append(" { ")
                .append(fieldName).append(varsCallBuilder.toString())
                .append(" { __typename } }");

        try {
            Map<String, Object> payload = new java.util.HashMap<>();
            payload.put("query", queryBuilder.toString());
            if (!variablesMap.isEmpty()) {
                payload.put("variables", variablesMap);
            }
            return objectMapper.writeValueAsString(payload);
        } catch (Exception e) {
            return "{\"query\": \"{ " + fieldName + " }\"}";
        }
    }

    private String getGraphQLTypeString(JsonNode typeNode) {
        String kind = typeNode.path("kind").asText();
        if ("NON_NULL".equals(kind)) {
            return getGraphQLTypeString(typeNode.path("ofType")) + "!";
        } else if ("LIST".equals(kind)) {
            return "[" + getGraphQLTypeString(typeNode.path("ofType")) + "]";
        }
        return typeNode.path("name").asText("String");
    }

    private Object getDummyValueObjectForType(JsonNode typeNode) {
        String typeName = typeNode.path("name").asText(null);
        String kind = typeNode.path("kind").asText();

        if ("NON_NULL".equals(kind)) {
            return getDummyValueObjectForType(typeNode.path("ofType"));
        } else if ("LIST".equals(kind)) {
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

package ch.hug.orthrusdast.scanner;

import ch.hug.orthrusdast.http.ScanHttpClient;
import ch.hug.orthrusdast.model.CWEReference;
import ch.hug.orthrusdast.model.Operation;
import ch.hug.orthrusdast.model.RiskLevel;
import ch.hug.orthrusdast.model.Vulnerability;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Scans for GraphQL Introspection enabled in production (Information Disclosure).
 */
@Component
public class GraphqlIntrospectionScanner implements SecurityScanner {

    private static final Logger log = LoggerFactory.getLogger(GraphqlIntrospectionScanner.class);
    private final ScanHttpClient httpClient;
    
    private static final String INTROSPECTION_QUERY = "{\"query\": \"query { __schema { queryType { name } } }\"}";

    public GraphqlIntrospectionScanner(ScanHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public String getId() {
        return "graphql-introspection";
    }

    @Override
    public String getName() {
        return "GraphQL Introspection Scanner";
    }

    @Override
    public Flux<Vulnerability> scan(Operation operation) {
        // We only want to test this once per URL, but since we receive Operations,
        // we'll just check if it's a POST request (typical for GraphQL) and test it.
        // If the body contains "query" or it's a known GraphQL endpoint.
        
        if (!"POST".equalsIgnoreCase(operation.method())) {
            return Flux.empty();
        }
        
        // Very basic heuristic: if it looks like a GraphQL operation (from GraphqlDiscoverer)
        if (operation.body() == null || !operation.body().contains("\"query\"")) {
            return Flux.empty();
        }

        log.debug("Scanning for GraphQL Introspection: {}", operation.url());

        Operation testOp = new Operation(
                operation.url(),
                "POST",
                Map.of("Content-Type", "application/json"),
                Collections.emptyMap(),
                INTROSPECTION_QUERY,
                operation.securityRequirements(),
                operation.expectedContentTypes(),
                operation.authScheme()
        );

        return httpClient.send(testOp)
                .flatMapMany(response -> {
                    if (response.statusCode().is2xxSuccessful() && response.bodyContains("__schema")) {
                        Vulnerability vuln = createVulnerabilityWithTrace(
                                "GraphQL Introspection Enabled",
                                "The GraphQL endpoint has introspection enabled, exposing the entire API schema.",
                                RiskLevel.LOW,
                                Vulnerability.Confidence.HIGH,
                                operation,
                                CWEReference.CWE_200, // Information Exposure
                                List.of("CAPEC-118"),
                                4.3,
                                "The server responded with the schema details to an introspection query.",
                                "Disable GraphQL introspection in production environments.", testOp, response,
                                    "API Endpoint (Network)",
                                    "Unauthorized Access / Data Exposure");
                        return Flux.just(vuln);
                    }
                    return Flux.empty();
                });
    }

    private String truncate(String text) {
        if (text == null) return "null";
        return text.length() > 200 ? text.substring(0, 200) + "..." : text;
    }
}

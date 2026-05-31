package ch.hug.orthrusdast.scanner;


import ch.hug.orthrusdast.http.ScanHttpClient;
import ch.hug.orthrusdast.model.CWEReference;
import ch.hug.orthrusdast.model.Operation;
import ch.hug.orthrusdast.model.RiskLevel;
import ch.hug.orthrusdast.model.Vulnerability;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;

import java.util.List;

/**
 * Scans for GraphQL Denial of Service via deeply nested queries (CWE-400/CWE-770).
 */
@Component
public class GraphqlDosScanner implements SecurityScanner {

    private final ScanHttpClient httpClient;
    
    // A generic highly nested GraphQL query targeting common nodes
    private static final String NESTED_QUERY = "{\"query\":\"query { system { user { system { user { system { user { system { user { id } } } } } } } } }\"}";

    public GraphqlDosScanner(ScanHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public String getId() {
        return "graphql-dos";
    }

    @Override
    public String getName() {
        return "GraphQL DoS Scanner";
    }

    @Override
    public Flux<Vulnerability> scan(Operation operation) {
        // Only target GraphQL endpoints
        if (!operation.url().toLowerCase().contains("graphql") && 
            !(operation.expectedContentTypes() != null && operation.expectedContentTypes().contains("application/graphql"))) {
            return Flux.empty();
        }

        if (!"POST".equals(operation.method().toUpperCase())) {
            return Flux.empty();
        }

        java.util.Map<String, String> newHeaders = new java.util.HashMap<>(operation.headers());
        newHeaders.put("Content-Type", "application/json");

        Operation testOp = new Operation(
                operation.url(),
                operation.method(),
                newHeaders,
                operation.queryParams(),
                NESTED_QUERY,
                operation.securityRequirements(),
                operation.expectedContentTypes(),
                operation.authScheme()
        );

        long startTime = System.currentTimeMillis();

        return httpClient.send(testOp).flatMapMany(response -> {
            long duration = System.currentTimeMillis() - startTime;
            
            // If the server takes an unusually long time to process a malformed nested query or returns 500
            if (response.statusCode().is5xxServerError() || duration > 3000) {
                Vulnerability vuln = Vulnerability.createWithDetails(
                        "GraphQL Denial of Service (Nested Query)",
                        "The GraphQL endpoint allowed a deeply nested query, causing high response times or a server error. This indicates a lack of query depth limiting.",
                        RiskLevel.HIGH,
                        Vulnerability.Confidence.MEDIUM,
                        getId(),
                        operation,
                        CWEReference.CWE_770,
                        List.of("CAPEC-130"),
                        7.5,
                        "Server took " + duration + "ms or returned " + response.statusCode() + " when processing a highly nested query.",
                        "Implement GraphQL query depth limiting and cost analysis to prevent expensive queries from consuming server resources.",
                        "Injected a deeply nested GraphQL query: " + NESTED_QUERY,
                        "Response time: " + duration + "ms. Status: " + response.statusCode()
                ,
                                    "API Endpoint (Network)",
                                    "Unauthorized Access / Data Exposure");
                return Flux.just(vuln);
            }
            return Flux.empty();
        });
    }
}

package ch.nexsol.orthrusdast.scanner;

import java.util.List;

import ch.nexsol.orthrusdast.http.ScanHttpClient;
import ch.nexsol.orthrusdast.model.CWEReference;
import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.RiskLevel;
import ch.nexsol.orthrusdast.model.Vulnerability;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;

/**
 * Scans for Verbose Error Messages (CWE-209).
 */
@Component
public class VerboseErrorScanner implements SecurityScanner {

    private final ScanHttpClient httpClient;
    private static final String MALFORMED_JSON = "{\"broken\": \"json\", \"unterminated_array\": [";

    public VerboseErrorScanner(ScanHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public String getId() {
        return "verbose-error";
    }

    @Override
    public String getName() {
        return "Verbose Error Scanner";
    }

    @Override
    public Flux<Vulnerability> scan(Operation operation) {
        return Flux.defer(() -> {
        Flux<Vulnerability> bodyVulns = Flux.empty();
        Flux<Vulnerability> queryVulns = Flux.empty();

        String method = operation.method().toUpperCase();
        if ("POST".equals(method) || "PUT".equals(method) || "PATCH".equals(method)) {
            Operation testOpBody = new Operation(
                    operation.url(), operation.method(), operation.headers(), operation.queryParams(),
                    MALFORMED_JSON, operation.securityRequirements(), operation.expectedContentTypes(), operation.authScheme()
            );
            bodyVulns = executeErrorCheck(testOpBody, operation, "sending malformed JSON in the request body");
        }

        if (operation.queryParams() != null && !operation.queryParams().isEmpty()) {
            Map<String, String> badQueryParams = new HashMap<>();
            for (Map.Entry<String, String> entry : operation.queryParams().entrySet()) {
                // Replace numbers with strings, and strings with extreme symbols
                String val = entry.getValue();
                if (val.matches("\\d+")) {
                    badQueryParams.put(entry.getKey(), "not_a_number_'\"[]{}");
                } else {
                    badQueryParams.put(entry.getKey(), val + "%00%ff'\"");
                }
            }
            
            Operation testOpQuery = new Operation(
                    operation.url(), operation.method(), operation.headers(), badQueryParams,
                    operation.body(), operation.securityRequirements(), operation.expectedContentTypes(), operation.authScheme()
            );
            queryVulns = executeErrorCheck(testOpQuery, operation, "sending malformed or type-mismatched query parameters");
        }

        return Flux.concat(bodyVulns, queryVulns);
            });
    }

    private Flux<Vulnerability> executeErrorCheck(Operation testOp, Operation originalOp, String context) {
        return httpClient.send(testOp)
                .flatMapMany(response -> {
                    // Look for stack traces or framework names
                    if (response.bodyContains("java.lang.") || 
                        response.bodyContains("org.springframework") ||
                        response.bodyContains("Traceback (most recent call last)") ||
                        response.bodyContains("node_modules") ||
                        response.bodyContains("SQL syntax") ||
                        response.bodyContains("mysql_fetch") ||
                        response.bodyContains("ORA-") ||
                        response.bodyContains("Fatal error: Uncaught") ||
                        response.bodyContains("System.Data.SqlClient.SqlException") ||
                        response.bodyContains("ActionController::RoutingError")) {
                        
                        Vulnerability vuln = createVulnerabilityWithTrace(
                                "Verbose Error Information Leak",
                                "The endpoint returns detailed error messages or stack traces when processing invalid input.",
                                RiskLevel.MEDIUM,
                                Vulnerability.Confidence.HIGH,
                                originalOp,
                                CWEReference.CWE_209,
                                List.of("CAPEC-54"),
                                5.3,
                                "Response contains stack traces or framework-specific internal errors after " + context + ".",
                                "Configure your framework to return generic error messages to the client. Log detailed errors internally only.", testOp, response,
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

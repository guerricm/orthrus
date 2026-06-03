package ch.hug.orthrusdast.scanner;

import java.util.List;

import ch.hug.orthrusdast.http.ScanHttpClient;
import ch.hug.orthrusdast.model.CWEReference;
import ch.hug.orthrusdast.model.Operation;
import ch.hug.orthrusdast.model.RiskLevel;
import ch.hug.orthrusdast.model.Vulnerability;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;

import java.util.HashMap;
import java.util.Map;

/**
 * Scans for NoSQL Injection (CWE-943).
 */
@Component
public class NoSqlInjectionScanner implements SecurityScanner {

    private final ScanHttpClient httpClient;
    
    // Using common NoSQL injection payloads that often bypass authentication or where clauses (MongoDB focused)
    private static final String PAYLOAD_1 = "{\"$ne\": null}";
    private static final String PAYLOAD_2 = "{\"$gt\": \"\"}";

    public NoSqlInjectionScanner(ScanHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public String getId() {
        return "nosql-injection";
    }

    @Override
    public String getName() {
        return "NoSQL Injection Scanner";
    }

    @Override
    public Flux<Vulnerability> scan(Operation operation) {
        if (operation.queryParams() != null && !operation.queryParams().isEmpty()) {
            return Flux.fromIterable(operation.queryParams().keySet())
                    .flatMap(paramName -> testParam(operation, paramName, PAYLOAD_1).switchIfEmpty(testParam(operation, paramName, PAYLOAD_2)));
        }
        return Flux.empty();
    }
    
    private Flux<Vulnerability> testParam(Operation operation, String paramName, String payload) {
        Map<String, String> modifiedParams = new HashMap<>(operation.queryParams());
        modifiedParams.put(paramName, payload);
        
        Operation testOp = new Operation(
                operation.url(),
                operation.method(),
                operation.headers(),
                modifiedParams,
                operation.body(),
                operation.securityRequirements(),
                operation.expectedContentTypes(),
                operation.authScheme()
        );
        
        return httpClient.send(testOp)
                .flatMapMany(response -> {
                    // Check for typical NoSQL error messages to avoid false positives on generic 500 errors
                    if (response.bodyContainsExact("MongoError") || response.bodyContainsExact("MongoServerError") || response.bodyContainsExact("Cast to ObjectId failed")) {
                         Vulnerability vuln = createVulnerabilityWithTrace(
                            "Potential NoSQL Injection",
                            "The endpoint might be vulnerable to NoSQL Injection (e.g., MongoDB).",
                            RiskLevel.HIGH,
                            Vulnerability.Confidence.MEDIUM,
                            operation,
                            CWEReference.CWE_943,
                            List.of("CAPEC-66"),
                                9.8,
                            "Response indicates a NoSQL database error when payload '" + payload + "' was injected.",
                            "Validate and sanitize input. Use safe APIs that parameterize queries rather than concatenating strings or blindly passing JSON structures to the database driver.", testOp, response,
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

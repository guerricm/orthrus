package ch.hug.vulnapi.scanner;

import ch.hug.vulnapi.http.ScanHttpClient;
import ch.hug.vulnapi.model.CWEReference;
import ch.hug.vulnapi.model.Operation;
import ch.hug.vulnapi.model.RiskLevel;
import ch.hug.vulnapi.model.Vulnerability;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import java.util.Map;

/**
 * Scans for SQL Injection vulnerabilities (CWE-89).
 */
@Component
public class SqlInjectionScanner implements SecurityScanner {

    private static final Logger log = LoggerFactory.getLogger(SqlInjectionScanner.class);
    private final ScanHttpClient httpClient;
    
    private static final String PAYLOAD_1 = "' OR '1'='1";
    private static final String PAYLOAD_2 = "1; DROP TABLE users";

    public SqlInjectionScanner(ScanHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public String getId() {
        return "sqli";
    }

    @Override
    public String getName() {
        return "SQL Injection Scanner";
    }

    @Override
    public Flux<Vulnerability> scan(Operation operation) {
        log.debug("Scanning for SQL Injection: {}", operation.url());

        // Basic check: Inject into URL if there are query parameters
        if (operation.queryParams() != null && !operation.queryParams().isEmpty()) {
            return Flux.fromIterable(operation.queryParams().keySet())
                    .flatMap(paramName -> testParam(operation, paramName, PAYLOAD_1));
        }

        return Flux.empty();
    }
    
    private Flux<Vulnerability> testParam(Operation operation, String paramName, String payload) {
        Map<String, String> modifiedParams = new java.util.HashMap<>(operation.queryParams());
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
                    // Very simplistic detection based on common SQL error strings
                    if (response.statusCode().is5xxServerError() || response.bodyContains("syntax error") || response.bodyContains("mysql_fetch")) {
                         Vulnerability vuln = Vulnerability.createWithDetails(
                            "Potential SQL Injection",
                            "The endpoint might be vulnerable to SQL Injection in parameter '" + paramName + "'.",
                            RiskLevel.HIGH,
                            Vulnerability.Confidence.MEDIUM,
                            getId(),
                            operation,
                            CWEReference.CWE_89,
                            "Injection",
                            "Response indicates a database error when payload '" + payload + "' was injected.",
                            "Use parameterized queries or prepared statements.",
                            "Injected payload into query param: " + paramName + "=" + payload,
                            "Status: " + response.statusCode() + "\nBody snippet: " + truncate(response.body())
                        );
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

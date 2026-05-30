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
 * Scans for Sensitive Information Exposure in Query Strings (CWE-598).
 */
@Component
public class SensitiveQueryScanner implements SecurityScanner {

    private final ScanHttpClient httpClient;
    
    private static final List<String> SENSITIVE_KEYWORDS = List.of(
            "password", "pwd", "token", "secret", "apikey", "api_key", "auth", "session"
    );

    public SensitiveQueryScanner(ScanHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public String getId() {
        return "sensitive-query-params";
    }

    @Override
    public String getName() {
        return "Sensitive Query Parameters Scanner";
    }

    @Override
    public Flux<Vulnerability> scan(Operation operation) {
        if (!"GET".equals(operation.method().toUpperCase())) {
            return Flux.empty();
        }

        // Check if any query parameter name matches a sensitive keyword
        for (String paramName : operation.queryParams().keySet()) {
            String lowerParam = paramName.toLowerCase();
            for (String keyword : SENSITIVE_KEYWORDS) {
                if (lowerParam.contains(keyword)) {
                    Vulnerability vuln = Vulnerability.createWithDetails(
                            "Sensitive Information in Query String",
                            "The endpoint accepts a parameter named '" + paramName + "' in the URL query string. Query strings are logged by reverse proxies, web servers, and browser histories, leading to sensitive data exposure.",
                            RiskLevel.MEDIUM,
                            Vulnerability.Confidence.HIGH,
                            getId(),
                            operation,
                            CWEReference.CWE_598,
                            "Security Misconfiguration",
                            List.of("CAPEC-87"),
                            6.5,
                            "Parameter '" + paramName + "' found in GET request.",
                            "Move sensitive data from the query string to HTTP Headers (e.g., Authorization header) or the request body (e.g., POST request).",
                            "URL requested: " + operation.url() + " with parameter " + paramName,
                            "N/A"
                    );
                    return Flux.just(vuln);
                }
            }
        }

        return Flux.empty();
    }
}

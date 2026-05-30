package ch.hug.orthrusdast.scanner;
import java.util.List;

import ch.hug.orthrusdast.http.ScanHttpClient;
import ch.hug.orthrusdast.model.CWEReference;
import ch.hug.orthrusdast.model.Operation;
import ch.hug.orthrusdast.model.RiskLevel;
import ch.hug.orthrusdast.model.Vulnerability;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import java.util.Map;
import java.util.HashMap;

/**
 * Scans for SSRF (Server-Side Request Forgery) (CWE-918).
 */
@Component
public class SsrfScanner implements SecurityScanner {

    private final ScanHttpClient httpClient;
    
    // AWS Metadata endpoint as a common SSRF target
    private static final String PAYLOAD = "http://169.254.169.254/latest/meta-data/";

    public SsrfScanner(ScanHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public String getId() {
        return "ssrf";
    }

    @Override
    public String getName() {
        return "SSRF Scanner";
    }

    @Override
    public Flux<Vulnerability> scan(Operation operation) {
        if (operation.queryParams() != null && !operation.queryParams().isEmpty()) {
            return Flux.fromIterable(operation.queryParams().keySet())
                    .filter(param -> isPotentialUrlParam(param))
                    .flatMap(paramName -> testParam(operation, paramName));
        }
        return Flux.empty();
    }
    
    private boolean isPotentialUrlParam(String paramName) {
        String lower = paramName.toLowerCase();
        return lower.contains("url") || lower.contains("uri") || lower.contains("path") || lower.contains("host") || lower.contains("redirect") || lower.contains("target");
    }

    private Flux<Vulnerability> testParam(Operation operation, String paramName) {
        Map<String, String> modifiedParams = new HashMap<>(operation.queryParams());
        modifiedParams.put(paramName, PAYLOAD);
        
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
                    // Check if response contains typical AWS metadata strings or if it timed out trying to reach the internal IP
                    if (response.bodyContains("ami-id") || response.bodyContains("instance-id") || response.bodyContains("local-hostname")) {
                         Vulnerability vuln = Vulnerability.createWithDetails(
                            "Server-Side Request Forgery (SSRF)",
                            "The endpoint appears vulnerable to SSRF. It fetched data from the internal AWS metadata service.",
                            RiskLevel.CRITICAL,
                            Vulnerability.Confidence.HIGH,
                            getId(),
                            operation,
                            CWEReference.CWE_918,
                            "SSRF",
                                List.of("CAPEC-664"),
                                8.6,
                            "Response contains AWS metadata elements when parameter '" + paramName + "' was set to " + PAYLOAD,
                            "Validate and sanitize all user-supplied URLs. Use an allowlist of permitted domains.",
                            "Injected SSRF payload into query param: " + paramName + "=" + PAYLOAD,
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

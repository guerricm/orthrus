package ch.hug.vulnapi.scanner;
import java.util.List;

import ch.hug.vulnapi.http.ScanHttpClient;
import ch.hug.vulnapi.model.CWEReference;
import ch.hug.vulnapi.model.Operation;
import ch.hug.vulnapi.model.RiskLevel;
import ch.hug.vulnapi.model.Vulnerability;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;

/**
 * Scans for HTTP Method Tampering (CWE-650).
 */
@Component
public class HttpMethodTamperingScanner implements SecurityScanner {

    private final ScanHttpClient httpClient;
    // Methods that are typically not expected for data retrieval/modification if not explicitly defined
    private static final String[] UNUSUAL_METHODS = {"TRACE", "TRACK", "DEBUG"};

    public HttpMethodTamperingScanner(ScanHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public String getId() {
        return "method-tampering";
    }

    @Override
    public String getName() {
        return "HTTP Method Tampering Scanner";
    }

    @Override
    public Flux<Vulnerability> scan(Operation operation) {
        return Flux.fromArray(UNUSUAL_METHODS)
                .flatMap(method -> testMethod(operation, method));
    }

    private Flux<Vulnerability> testMethod(Operation operation, String method) {
        Operation testOp = new Operation(
                operation.url(),
                method,
                operation.headers(),
                operation.queryParams(),
                null, // No body for these methods usually
                operation.securityRequirements(),
                operation.expectedContentTypes(),
                operation.authScheme()
        );

        return httpClient.send(testOp)
                .flatMapMany(response -> {
                    // If TRACE is enabled and returns 200, it's a known vulnerability (Cross-Site Tracing - XST)
                    if ("TRACE".equals(method) && response.isSuccessful() && response.bodyContainsExact("TRACE /")) {
                        Vulnerability vuln = Vulnerability.createWithDetails(
                                "HTTP TRACE Method Enabled",
                                "The server supports the HTTP TRACE method, which can be exploited for Cross-Site Tracing (XST) attacks.",
                                RiskLevel.MEDIUM,
                                Vulnerability.Confidence.HIGH,
                                getId(),
                                operation,
                                CWEReference.CWE_650,
                                "Security Misconfiguration",
                                List.of("CAPEC-274"),
                                5.3,
                                "Server responded with 200 OK and reflected the request when using the TRACE method.",
                                "Disable the HTTP TRACE method on the web server.",
                                "Sent TRACE request to " + operation.url(),
                                "Status: " + response.statusCode() + "\nReflected Body: " + truncate(response.body())
                        );
                        return Flux.just(vuln);
                    } else if (!"TRACE".equals(method) && response.isSuccessful()) {
                         // Some other unusual method worked
                         Vulnerability vuln = Vulnerability.createWithDetails(
                                "Unusual HTTP Method Supported",
                                "The server successfully processes requests using the '" + method + "' HTTP method, which might lead to bypasses.",
                                RiskLevel.LOW,
                                Vulnerability.Confidence.MEDIUM,
                                getId(),
                                operation,
                                CWEReference.CWE_650,
                                "Security Misconfiguration",
                                List.of("CAPEC-274"),
                                5.3,
                                "Server responded with " + response.statusCode() + " when using the " + method + " method.",
                                "Restrict accepted HTTP methods to only those strictly necessary (e.g., GET, POST, PUT, DELETE).",
                                "Sent " + method + " request to " + operation.url(),
                                "Status: " + response.statusCode()
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

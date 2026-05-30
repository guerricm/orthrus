package ch.hug.orthrusdast.scanner;
import java.util.List;

import ch.hug.orthrusdast.http.ScanHttpClient;
import ch.hug.orthrusdast.model.CWEReference;
import ch.hug.orthrusdast.model.Operation;
import ch.hug.orthrusdast.model.RiskLevel;
import ch.hug.orthrusdast.model.Vulnerability;
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
        String method = operation.method().toUpperCase();
        if (!("POST".equals(method) || "PUT".equals(method) || "PATCH".equals(method))) {
            return Flux.empty(); // Mostly useful where body is expected
        }

        Operation testOp = new Operation(
                operation.url(),
                operation.method(),
                operation.headers(),
                operation.queryParams(),
                MALFORMED_JSON, // Inject malformed JSON
                operation.securityRequirements(),
                operation.expectedContentTypes(),
                operation.authScheme()
        );

        return httpClient.send(testOp)
                .flatMapMany(response -> {
                    // Look for stack traces or framework names
                    if (response.bodyContains("java.lang.") || 
                        response.bodyContains("org.springframework") ||
                        response.bodyContains("Traceback (most recent call last)") ||
                        response.bodyContains("node_modules")) {
                        
                        Vulnerability vuln = Vulnerability.createWithDetails(
                                "Verbose Error Information Leak",
                                "The endpoint returns detailed error messages or stack traces when processing invalid input.",
                                RiskLevel.MEDIUM,
                                Vulnerability.Confidence.HIGH,
                                getId(),
                                operation,
                                CWEReference.CWE_209,
                                "Security Misconfiguration",
                                List.of("CAPEC-54"),
                                5.3,
                                "Response contains stack traces or framework-specific internal errors.",
                                "Configure your framework to return generic error messages to the client. Log detailed errors internally only.",
                                "Sent malformed JSON body: " + MALFORMED_JSON,
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

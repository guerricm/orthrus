package ch.hug.orthrusdast.scanner;

import java.util.List;

import ch.hug.orthrusdast.http.ScanHttpClient;
import ch.hug.orthrusdast.model.CWEReference;
import ch.hug.orthrusdast.model.Operation;
import ch.hug.orthrusdast.model.RiskLevel;
import ch.hug.orthrusdast.model.Vulnerability;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;

/**
 * Scans for Broken Authentication (CWE-306, CWE-287).
 * Checks if an endpoint that usually requires auth is accessible without it or with invalid auth.
 */
@Component
public class BrokenAuthenticationScanner implements SecurityScanner {

    private static final Logger log = LoggerFactory.getLogger(BrokenAuthenticationScanner.class);
    private final ScanHttpClient httpClient;

    public BrokenAuthenticationScanner(ScanHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public String getId() {
        return "broken-auth";
    }

    @Override
    public String getName() {
        return "Broken Authentication Scanner";
    }

    @Override
    public Flux<Vulnerability> scan(Operation operation) {
        log.debug("Scanning for Broken Authentication: {}", operation.url());

        // We care if the endpoint supposedly requires auth, if we can guess it's sensitive, or if it modifies state
        boolean isStateChanging = List.of("POST", "PUT", "PATCH", "DELETE").contains(operation.method().toUpperCase());
        boolean seemsSensitive = isStateChanging || operation.url().contains("/admin") || operation.url().contains("/private") || operation.authScheme() != null;
        
        if (!seemsSensitive) {
            return Flux.empty();
        }

        // Test 1: Send request WITHOUT any auth
        Operation noAuthOp = new Operation(
                operation.url(),
                operation.method(),
                operation.headers(), // Will not contain auth if injected via scheme
                operation.queryParams(),
                operation.body(),
                operation.securityRequirements(),
                operation.expectedContentTypes(),
                null // NO AUTH
        );

        return httpClient.send(noAuthOp)
                .flatMapMany(response -> {
                    if (response.isSuccessful()) {
                        Vulnerability vuln = Vulnerability.createWithDetails(
                                "Missing Authentication for Critical Function",
                                "The endpoint exposes sensitive operations without requiring authentication.",
                                RiskLevel.CRITICAL,
                                Vulnerability.Confidence.HIGH,
                                getId(),
                                operation,
                                CWEReference.CWE_306,
                                List.of("CAPEC-115"),
                                9.8,
                                "Endpoint returned " + response.statusCode() + " OK without any authentication credentials",
                                "Implement robust authentication for this endpoint.",
                                "Sent " + operation.method() + " request without Authorization header.",
                                "Status: " + response.statusCode() + "\nBody snippet: " + truncate(response.body())
                        ,
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

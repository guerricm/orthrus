package ch.nexsol.orthrusdast.scanner;

import java.util.List;

import ch.nexsol.orthrusdast.http.ScanHttpClient;
import ch.nexsol.orthrusdast.model.CWEReference;
import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.RiskLevel;
import ch.nexsol.orthrusdast.model.Vulnerability;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;

import java.util.HashMap;
import java.util.Map;

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
        return Flux.defer(() -> {
        log.debug("Scanning for Broken Authentication: {}", operation.url());

        // We care if the endpoint supposedly requires auth, if we can guess it's sensitive, or if it modifies state
        boolean isStateChanging = List.of("POST", "PUT", "PATCH", "DELETE").contains(operation.method().toUpperCase());
        boolean seemsSensitive = isStateChanging || operation.url().contains("/admin") || operation.url().contains("/private") || operation.authScheme() != null;
        
        if (!seemsSensitive) {
            return Flux.empty();
        }

        // Test 1: Send request WITHOUT any auth
        Operation noAuthOp = new Operation(
                operation.url(), operation.method(), operation.headers(), operation.queryParams(),
                operation.body(), operation.securityRequirements(), operation.expectedContentTypes(), null
        );

        // Test 2: Send request with GARBAGE auth
        Map<String, String> garbageHeaders = new HashMap<>(operation.headers() != null ? operation.headers() : new HashMap<>());
        garbageHeaders.put("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.signature");
        Operation garbageAuthOp = new Operation(
                operation.url(), operation.method(), garbageHeaders, operation.queryParams(),
                operation.body(), operation.securityRequirements(), operation.expectedContentTypes(), null
        );

        // Test 3: SQLi in Auth Header
        Map<String, String> sqliHeaders = new HashMap<>(operation.headers() != null ? operation.headers() : new HashMap<>());
        sqliHeaders.put("Authorization", "Bearer ' OR 1=1--");
        Operation sqliAuthOp = new Operation(
                operation.url(), operation.method(), sqliHeaders, operation.queryParams(),
                operation.body(), operation.securityRequirements(), operation.expectedContentTypes(), null
        );

        return Flux.concat(
            executeAuthCheck(noAuthOp, operation, "Missing Authentication", "Endpoint returned OK without any authentication credentials."),
            executeAuthCheck(garbageAuthOp, operation, "Invalid Authentication Accepted", "Endpoint returned OK despite a completely invalid/garbage token."),
            executeAuthCheck(sqliAuthOp, operation, "SQLi Bypass in Authentication", "Endpoint returned OK when injecting SQL into the Authorization header.")
        );
            });
    }
    
    private Flux<Vulnerability> executeAuthCheck(Operation testOp, Operation originalOp, String title, String evidence) {
        return httpClient.send(testOp)
                .flatMapMany(response -> {
                    if (response.isSuccessful() && !response.bodyContains("Unauthorized") && !response.bodyContains("Unauthenticated")) {
                        Vulnerability vuln = createVulnerabilityWithTrace(
                                title,
                                "The endpoint exposes sensitive operations without properly validating authentication.",
                                RiskLevel.CRITICAL,
                                Vulnerability.Confidence.HIGH,
                                originalOp,
                                CWEReference.CWE_306,
                                List.of("CAPEC-115"),
                                9.8,
                                evidence + " Status: " + response.statusCode(),
                                "Implement robust authentication for this endpoint.", testOp, response,
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

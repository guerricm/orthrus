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
 * Scans for missing Rate Limiting (CWE-799).
 */
@Component
public class RateLimitingScanner implements SecurityScanner {

    private final ScanHttpClient httpClient;
    private static final int REQUEST_COUNT = 30; // Number of rapid requests to send

    public RateLimitingScanner(ScanHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public String getId() {
        return "rate-limiting";
    }

    @Override
    public String getName() {
        return "Rate Limiting Scanner";
    }

    @Override
    public Flux<Vulnerability> scan(Operation operation) {
        // We only scan POST/PUT/DELETE for rate limiting to avoid overwhelming GET endpoints during general scans,
        // or specifically target login/auth endpoints.
        boolean isStateChanging = !operation.method().equalsIgnoreCase("GET") && !operation.method().equalsIgnoreCase("OPTIONS");
        boolean isAuthEndpoint = operation.url().toLowerCase().contains("login") || operation.url().toLowerCase().contains("auth") || operation.url().toLowerCase().contains("token");
        
        if (!isStateChanging && !isAuthEndpoint) {
            return Flux.empty();
        }

        // Send N requests rapidly
        return httpClient.sendNTimes(operation, REQUEST_COUNT)
                .flatMapMany(lastResponse -> {
                    // Check if the last response is 429 Too Many Requests
                    if (lastResponse.statusCode().value() != 429) {
                         Vulnerability vuln = createVulnerabilityWithTrace(
                                "Missing Rate Limiting",
                                "The endpoint does not seem to enforce rate limiting. " + REQUEST_COUNT + " rapid requests were sent without receiving a 429 Too Many Requests response.",
                                RiskLevel.MEDIUM,
                                Vulnerability.Confidence.LOW,
                                operation,
                                CWEReference.CWE_799,
                                List.of("CAPEC-115"),
                                5.3,
                                "After " + REQUEST_COUNT + " requests, the server returned status " + lastResponse.statusCode().value() + " instead of 429.",
                                "Implement rate limiting using a gateway, WAF, or application logic (e.g. token bucket algorithm).", operation, null,
                                    "API Endpoint (Network)",
                                    "Unauthorized Access / Data Exposure");
                        return Flux.just(vuln);
                    }
                    return Flux.empty();
                });
    }
}

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
 * Scans for Broken Function Level Authorization (BFLA) (API5:2023).
 */
@Component
public class BflaScanner implements SecurityScanner {

    private final ScanHttpClient httpClient;

    public BflaScanner(ScanHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public String getId() {
        return "bfla";
    }

    @Override
    public String getName() {
        return "Broken Function Level Auth Scanner";
    }

    @Override
    public Flux<Vulnerability> scan(Operation operation) {
        String method = operation.method().toUpperCase();
        
        // Strategy: If an endpoint is a standard GET, try sending a DELETE or PUT with the same auth.
        // If it works (2xx), it might be a BFLA if the user shouldn't have deletion rights.
        if (!"GET".equals(method)) {
            return Flux.empty();
        }

        Operation testOp = new Operation(
                operation.url(),
                "DELETE", // Try an administrative method on a read-only endpoint
                operation.headers(),
                operation.queryParams(),
                operation.body(),
                operation.securityRequirements(),
                operation.expectedContentTypes(),
                operation.authScheme()
        );

        return httpClient.send(testOp)
                .flatMapMany(response -> {
                    // If DELETE succeeds on an endpoint discovered as GET, flag for review
                    if (response.isSuccessful()) {
                        Vulnerability vuln = createVulnerabilityWithTrace(
                                "Potential Broken Function Level Authorization",
                                "The endpoint accepts administrative HTTP methods (like DELETE) even though it was discovered as a GET endpoint. Verify if the current user should have this privilege.",
                                RiskLevel.HIGH,
                                Vulnerability.Confidence.LOW, // Low confidence, depends on context
                                operation,
                                CWEReference.CWE_285,
                                List.of("CAPEC-115"),
                                9.8,
                                "Server returned " + response.statusCode() + " OK when sending a DELETE request to a GET endpoint.",
                                "Ensure function-level access control checks exist for all administrative operations and methods.",
                                testOp,
                                response,
                                    "API Endpoint (Network)",
                                    "Unauthorized Access / Data Exposure");
                        return Flux.just(vuln);
                    }
                    return Flux.empty();
                });
    }
}

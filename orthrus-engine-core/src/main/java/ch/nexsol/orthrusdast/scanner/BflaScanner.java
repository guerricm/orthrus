package ch.nexsol.orthrusdast.scanner;

import java.util.List;

import ch.nexsol.orthrusdast.http.ScanHttpClient;
import ch.nexsol.orthrusdast.model.CWEReference;
import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.RiskLevel;
import ch.nexsol.orthrusdast.model.Vulnerability;
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
        return Flux.defer(() -> {
        String method = operation.method().toUpperCase();
        Flux<Vulnerability> methodChangeVulns = Flux.empty();
        Flux<Vulnerability> methodOverrideVulns = Flux.empty();

        if ("GET".equals(method)) {
            // Try modifying state on a read-only endpoint
            methodChangeVulns = Flux.just("DELETE", "PUT", "POST")
                    .concatMap(testMethod -> executeBflaCheck(operation, testMethod, operation.headers(), "Changing HTTP Method from GET to " + testMethod));
        } else if ("POST".equals(method)) {
            // Try HTTP Method Override to bypass routing/WAF level checks
            java.util.Map<String, String> overrideHeaders = new java.util.HashMap<>(operation.headers() != null ? operation.headers() : new java.util.HashMap<>());
            overrideHeaders.put("X-HTTP-Method-Override", "DELETE");
            overrideHeaders.put("X-HTTP-Method", "DELETE");
            
            methodOverrideVulns = executeBflaCheck(operation, "POST", overrideHeaders, "Using X-HTTP-Method-Override header to simulate DELETE");
        }

        return Flux.concat(methodChangeVulns, methodOverrideVulns);
            });
    }

    private Flux<Vulnerability> executeBflaCheck(Operation operation, String testMethod, java.util.Map<String, String> testHeaders, String context) {
        Operation testOp = new Operation(
                operation.url(),
                testMethod,
                testHeaders,
                operation.queryParams(),
                operation.body(),
                operation.securityRequirements(),
                operation.expectedContentTypes(),
                operation.authScheme()
        );

        return httpClient.send(testOp)
                .flatMapMany(response -> {
                    if (response.isSuccessful() && !response.bodyContains("not allowed") && !response.bodyContains("Method Not Allowed")) {
                        Vulnerability vuln = createVulnerabilityWithTrace(
                                "Potential Broken Function Level Authorization",
                                "The endpoint accepts administrative or state-changing operations via BFLA bypass techniques. Verify if the current user should have this privilege.",
                                RiskLevel.HIGH,
                                Vulnerability.Confidence.LOW,
                                operation,
                                CWEReference.CWE_285,
                                List.of("CAPEC-115"),
                                9.8,
                                "Server returned " + response.statusCode() + " OK when " + context + ".",
                                "Ensure function-level access control checks exist for all administrative operations and methods. Reject unexpected HTTP Method Override headers.",
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

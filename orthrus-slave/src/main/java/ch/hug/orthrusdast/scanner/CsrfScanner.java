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
 * Scans for Cross-Site Request Forgery (CSRF) vulnerabilities (CWE-352).
 */
@Component
public class CsrfScanner implements SecurityScanner {

    private final ScanHttpClient httpClient;

    public CsrfScanner(ScanHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public String getId() {
        return "csrf-protection";
    }

    @Override
    public String getName() {
        return "CSRF Protection Scanner";
    }

    @Override
    public Flux<Vulnerability> scan(Operation operation) {
        // Only target state-changing methods
        if (!List.of("POST", "PUT", "DELETE", "PATCH").contains(operation.method().toUpperCase())) {
            return Flux.empty();
        }

        // Strategy: We strip any custom X-CSRF or Origin headers and send the request.
        // If it still succeeds with a 2xx, and relies on cookies for auth, it might be vulnerable.
        java.util.Map<String, String> newHeaders = new java.util.HashMap<>(operation.headers());
        newHeaders.keySet().removeIf(k -> k.toLowerCase().contains("csrf") || k.toLowerCase().contains("xsrf"));
        newHeaders.put("Origin", "https://malicious-website.com");

        Operation testOp = new Operation(
                operation.url(),
                operation.method(),
                newHeaders,
                operation.queryParams(),
                operation.body(),
                operation.securityRequirements(),
                operation.expectedContentTypes(),
                operation.authScheme()
        );

        return httpClient.send(testOp).flatMapMany(response -> {
            if (response.isSuccessful()) {
                Vulnerability vuln = createVulnerabilityWithTrace(
                        "Potential Cross-Site Request Forgery (CSRF)",
                        "The state-changing endpoint allowed a request originating from an untrusted Origin without requiring an explicit Anti-CSRF token in the headers. If this API relies on Cookie-based authentication, it is vulnerable to CSRF.",
                        RiskLevel.MEDIUM,
                        Vulnerability.Confidence.LOW,
                        operation,
                        CWEReference.CWE_352,
                        List.of("CAPEC-62"),
                        6.5,
                        "Server accepted the request with Origin: https://malicious-website.com and no CSRF tokens.",
                        "Implement Anti-CSRF tokens (Synchronizer Token Pattern) for all state-changing endpoints if using Cookie authentication. Ensure cookies have the SameSite=Lax or Strict attribute.", testOp, response,
                                    "API Endpoint (Network)",
                                    "Unauthorized Access / Data Exposure");
                return Flux.just(vuln);
            }
            return Flux.empty();
        });
    }
}

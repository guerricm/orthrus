package ch.nexsol.orthrusdast.scanner;


import ch.nexsol.orthrusdast.http.ScanHttpClient;
import ch.nexsol.orthrusdast.model.CWEReference;
import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.RiskLevel;
import ch.nexsol.orthrusdast.model.Vulnerability;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;

import java.util.List;

/**
 * Scans for HTTP Request Smuggling (CWE-444).
 */
@Component
public class RequestSmugglingScanner implements SecurityScanner {

    private final ScanHttpClient httpClient;

    public RequestSmugglingScanner(ScanHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public String getId() {
        return "request-smuggling";
    }

    @Override
    public String getName() {
        return "HTTP Request Smuggling Scanner";
    }

    @Override
    public Flux<Vulnerability> scan(Operation operation) {
        if (!List.of("POST", "PUT", "PATCH").contains(operation.method().toUpperCase())) {
            return Flux.empty();
        }

        List<String> malformedTEs = List.of(
            "chunked, cow",
            "cow, chunked",
            " chunked",
            "chunked "
        );

        return Flux.fromIterable(malformedTEs).concatMap(te -> {
            java.util.Map<String, String> newHeaders = new java.util.HashMap<>(operation.headers());
            newHeaders.put("Transfer-Encoding", te);
            newHeaders.put("Content-Length", "4"); // Intentionally set conflicting CL (if http client allows it)

            Operation testOp = new Operation(
                    operation.url(),
                    operation.method(),
                    newHeaders,
                    operation.queryParams(),
                    "0\r\n\r\n", // Empty chunked body
                    operation.securityRequirements(),
                    operation.expectedContentTypes(),
                    operation.authScheme()
            );

            return httpClient.send(testOp)
                    .onErrorResume(e -> reactor.core.publisher.Mono.empty()) // Client might reject it locally
                    .flatMapMany(response -> {
                // If the server accepted the malformed TE header without a 400 Bad Request,
                // it might be vulnerable to HTTP Desync attacks if a frontend proxy parses it differently.
                if (response.statusCode().is2xxSuccessful() || response.statusCode().is5xxServerError()) {
                    Vulnerability vuln = createVulnerabilityWithTrace(
                            "Potential HTTP Request Smuggling (TE.TE / CL.TE)",
                            "⚠️ FALSE POSITIVES LIKELY: Manual testing required! The server accepted an ambiguous Transfer-Encoding header without returning a 400 Bad Request. If this server sits behind a proxy or load balancer, it might be vulnerable to HTTP Request Smuggling.",
                            RiskLevel.HIGH,
                            Vulnerability.Confidence.LOW,
                            operation,
                            CWEReference.CWE_444,
                            List.of("CAPEC-33", "CAPEC-272"),
                            7.5,
                            "Server responded with " + response.statusCode() + " instead of 400 when sending a malformed Transfer-Encoding header: '" + te + "'.",
                            "Ensure the frontend proxy and backend server interpret the Transfer-Encoding and Content-Length headers consistently. Reject requests with ambiguous or duplicated headers. Prefer using HTTP/2.", testOp, response,
                                        "API Endpoint (Network)",
                                        "Unauthorized Access / Data Exposure");
                    return Flux.just(vuln);
                }
                return Flux.empty();
            });
        });
    }
}

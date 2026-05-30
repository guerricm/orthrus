package ch.hug.orthrusdast.scanner;

import ch.hug.orthrusdast.http.ScanHttpClient;
import ch.hug.orthrusdast.model.CWEReference;
import ch.hug.orthrusdast.model.Operation;
import ch.hug.orthrusdast.model.RiskLevel;
import ch.hug.orthrusdast.model.Vulnerability;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;

import java.util.ArrayList;
import java.util.List;

/**
 * Scans for missing or misconfigured security headers.
 */
@Component
public class SecurityHeadersScanner implements SecurityScanner {

    private final ScanHttpClient httpClient;

    public SecurityHeadersScanner(ScanHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public String getId() {
        return "security-headers";
    }

    @Override
    public String getName() {
        return "Security Headers Scanner";
    }

    @Override
    public Flux<Vulnerability> scan(Operation operation) {
        return httpClient.send(operation).flatMapMany(response -> {
            List<Vulnerability> vulns = new ArrayList<>();

            checkHeader(response, "Strict-Transport-Security", "HSTS", CWEReference.CWE_693, operation, vulns);
            checkHeader(response, "X-Content-Type-Options", "X-Content-Type-Options", CWEReference.CWE_693, operation, vulns);
            checkHeader(response, "X-Frame-Options", "X-Frame-Options", CWEReference.CWE_1021, operation, vulns);
            checkHeader(response, "Content-Security-Policy", "CSP", CWEReference.CWE_693, operation, vulns);

            return Flux.fromIterable(vulns);
        });
    }

    private void checkHeader(ch.hug.orthrusdast.http.ScanHttpResponse response, String headerName, String shortName, CWEReference cwe, Operation operation, List<Vulnerability> vulns) {
        if (!response.hasHeader(headerName)) {
            vulns.add(Vulnerability.createWithDetails(
                    "Missing Security Header: " + shortName,
                    "The HTTP response does not contain the '" + headerName + "' security header.",
                    RiskLevel.LOW,
                    Vulnerability.Confidence.HIGH,
                    getId(),
                    operation,
                    cwe,
                    "Security Misconfiguration",
                    List.of("CAPEC-310"),
                    4.3,
                    "Header '" + headerName + "' is missing from the response.",
                    "Configure your web server or application framework to include the '" + headerName + "' header in all responses.",
                    "Sent standard " + operation.method() + " request.",
                    "Headers received: " + response.headers().toString()
            ));
        }
    }
}

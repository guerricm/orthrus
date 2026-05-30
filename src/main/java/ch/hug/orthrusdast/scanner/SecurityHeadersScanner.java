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

            checkServerInfoLeakage(response, operation, vulns);

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
        } else if ("Content-Security-Policy".equalsIgnoreCase(headerName)) {
            String cspValue = response.getHeader(headerName);
            if (cspValue != null && (cspValue.contains("unsafe-inline") || cspValue.contains("unsafe-eval"))) {
                vulns.add(Vulnerability.createWithDetails(
                        "Weak Security Header: CSP",
                        "The Content-Security-Policy header contains 'unsafe-inline' or 'unsafe-eval', which significantly reduces the protection against XSS attacks.",
                        RiskLevel.MEDIUM,
                        Vulnerability.Confidence.HIGH,
                        getId(),
                        operation,
                        cwe,
                        "Security Misconfiguration",
                        List.of("CAPEC-63"),
                        5.4,
                        "CSP value contains unsafe directives: " + cspValue,
                        "Remove 'unsafe-inline' and 'unsafe-eval' from your CSP and use nonces or hashes instead.",
                        "Sent standard " + operation.method() + " request.",
                        "CSP Header: " + cspValue
                ));
            }
        }
    }

    private void checkServerInfoLeakage(ch.hug.orthrusdast.http.ScanHttpResponse response, Operation operation, List<Vulnerability> vulns) {
        List<String> leakyHeaders = List.of("Server", "X-Powered-By", "X-AspNet-Version");
        for (String header : leakyHeaders) {
            String value = response.getHeader(header);
            if (value != null && !value.isBlank()) {
                // For Server header, we only care if it leaks a version or specific framework, not just "nginx"
                if (header.equals("Server") && !value.matches(".*[0-9/].*")) {
                    continue; // Generic server name like "cloudflare" or "nginx" without version is mostly fine
                }
                
                vulns.add(Vulnerability.createWithDetails(
                        "Information Exposure: " + header + " Header",
                        "The server leaks version information or technology stack details via the '" + header + "' header.",
                        RiskLevel.LOW,
                        Vulnerability.Confidence.HIGH,
                        getId(),
                        operation,
                        CWEReference.CWE_200,
                        "Information Exposure",
                        List.of("CAPEC-118"),
                        3.7,
                        "Header '" + header + "' reveals: " + value,
                        "Configure your web server to remove or mask the '" + header + "' header.",
                        "Sent standard " + operation.method() + " request.",
                        header + ": " + value
                ));
            }
        }
    }
}

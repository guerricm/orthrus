package ch.nexsol.orthrusdast.scanner;


import ch.nexsol.orthrusdast.http.ScanHttpClient;
import ch.nexsol.orthrusdast.model.CWEReference;
import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.RiskLevel;
import ch.nexsol.orthrusdast.model.Vulnerability;
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
            checkHeader(response, "Permissions-Policy", "Permissions-Policy", CWEReference.CWE_693, operation, vulns);
            checkHeader(response, "Referrer-Policy", "Referrer-Policy", CWEReference.CWE_693, operation, vulns);

            checkServerInfoLeakage(response, operation, vulns);

            return Flux.fromIterable(vulns);
        });
    }

    private void checkHeader(ch.nexsol.orthrusdast.http.ScanHttpResponse response, String headerName, String shortName, CWEReference cwe, Operation operation, List<Vulnerability> vulns) {
        if (!response.hasHeader(headerName)) {
            vulns.add(createVulnerabilityWithTrace(
                    "Missing Security Header: " + shortName,
                    "The HTTP response does not contain the '" + headerName + "' security header.",
                    RiskLevel.LOW,
                    Vulnerability.Confidence.HIGH,
                    operation,
                    cwe,
                    List.of("CAPEC-310"),
                    4.3,
                    "Header '" + headerName + "' is missing from the response.",
                    "Configure your web server or application framework to include the '" + headerName + "' header in all nulls.", operation, null,
                                    "API Endpoint (Network)",
                                    "Unauthorized Access / Data Exposure"));
        } else {
            String headerValue = response.getHeader(headerName);
            if ("Content-Security-Policy".equalsIgnoreCase(headerName)) {
                if (headerValue != null && (headerValue.contains("unsafe-inline") || headerValue.contains("unsafe-eval"))) {
                    vulns.add(createVulnerabilityWithTrace(
                            "Weak Security Header: CSP",
                            "The Content-Security-Policy header contains 'unsafe-inline' or 'unsafe-eval', which significantly reduces the protection against XSS attacks.",
                            RiskLevel.MEDIUM,
                            Vulnerability.Confidence.HIGH,
                            operation,
                            cwe,
                            List.of("CAPEC-63"),
                            5.4,
                            "CSP value contains unsafe directives: " + headerValue,
                            "Remove 'unsafe-inline' and 'unsafe-eval' from your CSP and use nonces or hashes instead.", operation, null,
                            "API Endpoint (Network)",
                            "Unauthorized Access / Data Exposure"));
                }
            } else if ("Strict-Transport-Security".equalsIgnoreCase(headerName)) {
                if (headerValue != null && (!headerValue.contains("max-age") || !headerValue.contains("includeSubDomains"))) {
                    vulns.add(createVulnerabilityWithTrace(
                            "Weak Security Header: HSTS",
                            "The Strict-Transport-Security (HSTS) header is present but misconfigured (missing max-age or includeSubDomains).",
                            RiskLevel.LOW,
                            Vulnerability.Confidence.HIGH,
                            operation,
                            cwe,
                            List.of("CAPEC-310"),
                            4.3,
                            "HSTS value is misconfigured: " + headerValue,
                            "Ensure HSTS has a large max-age (e.g., 31536000) and includes 'includeSubDomains'.", operation, null,
                            "API Endpoint (Network)",
                            "Unauthorized Access / Data Exposure"));
                }
            }
        }
    }

    private void checkServerInfoLeakage(ch.nexsol.orthrusdast.http.ScanHttpResponse response, Operation operation, List<Vulnerability> vulns) {
        List<String> leakyHeaders = List.of("Server", "X-Powered-By", "X-AspNet-Version");
        for (String header : leakyHeaders) {
            String value = response.getHeader(header);
            if (value != null && !value.isBlank()) {
                // For Server header, we only care if it leaks a version or specific framework, not just "nginx"
                if (header.equals("Server") && !value.matches(".*[0-9/].*")) {
                    continue; // Generic server name like "cloudflare" or "nginx" without version is mostly fine
                }
                
                vulns.add(createVulnerabilityWithTrace(
                        "Information Exposure: " + header + " Header",
                        "The server leaks version information or technology stack details via the '" + header + "' header.",
                        RiskLevel.LOW,
                        Vulnerability.Confidence.HIGH,
                        operation,
                        CWEReference.CWE_200,
                        List.of("CAPEC-118"),
                        3.7,
                        "Header '" + header + "' reveals: " + value,
                        "Configure your web server to remove or mask the '" + header + "' header.", operation, null,
                                    "API Endpoint (Network)",
                                    "Unauthorized Access / Data Exposure"));
            }
        }
    }
}

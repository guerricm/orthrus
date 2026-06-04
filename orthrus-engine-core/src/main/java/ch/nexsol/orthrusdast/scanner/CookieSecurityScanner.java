package ch.nexsol.orthrusdast.scanner;


import ch.nexsol.orthrusdast.http.ScanHttpClient;
import ch.nexsol.orthrusdast.model.CWEReference;
import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.RiskLevel;
import ch.nexsol.orthrusdast.model.Vulnerability;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;

import java.util.ArrayList;
import java.util.List;

/**
 * Scans for missing security attributes in cookies (Secure, HttpOnly, SameSite).
 */
@Component
public class CookieSecurityScanner implements SecurityScanner {

    private final ScanHttpClient httpClient;

    public CookieSecurityScanner(ScanHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public String getId() {
        return "cookie-security";
    }

    @Override
    public String getName() {
        return "Cookie Security Scanner";
    }

    @Override
    public Flux<Vulnerability> scan(Operation operation) {
        return httpClient.send(operation).flatMapMany(response -> {
            List<Vulnerability> vulns = new ArrayList<>();

            List<String> cookies = response.headers().get(HttpHeaders.SET_COOKIE);
            if (cookies != null && !cookies.isEmpty()) {
                for (String cookie : cookies) {
                    checkCookie(cookie, operation, vulns, response);
                }
            }

            return Flux.fromIterable(vulns);
        });
    }

    private void checkCookie(String cookie, Operation operation, List<Vulnerability> vulns, ch.nexsol.orthrusdast.http.ScanHttpResponse response) {
        String lowerCookie = cookie.toLowerCase();
        String cookieName = cookie.split("=")[0].trim();

        if (!lowerCookie.contains("secure")) {
            vulns.add(createVulnerabilityWithTrace(
                    "Missing 'Secure' Cookie Attribute",
                    "The cookie '" + cookieName + "' is missing the 'Secure' attribute. This means the cookie could be transmitted in cleartext over unencrypted HTTP connections.",
                    RiskLevel.MEDIUM,
                    Vulnerability.Confidence.HIGH,
                    operation,
                    CWEReference.CWE_614,
                    List.of("CAPEC-31"),
                    5.3,
                    "Set-Cookie header found without 'Secure' flag: " + cookie,
                    "Always set the 'Secure' flag for sensitive cookies so they are only transmitted over HTTPS.", operation, null,
                                    "API Endpoint (Network)",
                                    "Unauthorized Access / Data Exposure"));
        }

        if (!lowerCookie.contains("httponly")) {
            vulns.add(createVulnerabilityWithTrace(
                    "Missing 'HttpOnly' Cookie Attribute",
                    "The cookie '" + cookieName + "' is missing the 'HttpOnly' attribute. This exposes the cookie to Cross-Site Scripting (XSS) attacks, allowing client-side scripts to read its value.",
                    RiskLevel.MEDIUM,
                    Vulnerability.Confidence.HIGH,
                    operation,
                    CWEReference.CWE_1004,
                    List.of("CAPEC-31"),
                    5.3,
                    "Set-Cookie header found without 'HttpOnly' flag: " + cookie,
                    "Always set the 'HttpOnly' flag for session identifiers and sensitive cookies to prevent access from JavaScript.", operation, null,
                                    "API Endpoint (Network)",
                                    "Unauthorized Access / Data Exposure"));
        }

        if (!lowerCookie.contains("samesite")) {
            vulns.add(createVulnerabilityWithTrace(
                    "Missing 'SameSite' Cookie Attribute",
                    "The cookie '" + cookieName + "' is missing the 'SameSite' attribute. This increases the risk of Cross-Site Request Forgery (CSRF) attacks.",
                    RiskLevel.LOW,
                    Vulnerability.Confidence.HIGH,
                    operation,
                    CWEReference.CWE_1275,
                    List.of("CAPEC-62"),
                    4.3,
                    "Set-Cookie header found without 'SameSite' attribute: " + cookie,
                    "Configure the cookie with 'SameSite=Lax' or 'SameSite=Strict' to restrict cross-site sharing.", operation, null,
                                    "API Endpoint (Network)",
                                    "Unauthorized Access / Data Exposure"));
        } else if (lowerCookie.contains("samesite=none") && !lowerCookie.contains("secure")) {
            vulns.add(createVulnerabilityWithTrace(
                    "Invalid Cookie Configuration: SameSite=None without Secure",
                    "The cookie '" + cookieName + "' is configured with 'SameSite=None' but is missing the 'Secure' attribute. Modern browsers will reject this cookie.",
                    RiskLevel.MEDIUM,
                    Vulnerability.Confidence.HIGH,
                    operation,
                    CWEReference.CWE_614,
                    List.of("CAPEC-31"),
                    5.3,
                    "Set-Cookie header has 'SameSite=None' but lacks 'Secure': " + cookie,
                    "Always set the 'Secure' flag when using 'SameSite=None'.", operation, null,
                                    "API Endpoint (Network)",
                                    "Unauthorized Access / Data Exposure"));
        }

        if (lowerCookie.contains("domain=")) {
            String domain = extractAttribute(cookie, "domain");
            if (domain != null && domain.startsWith(".")) {
                vulns.add(createVulnerabilityWithTrace(
                    "Overly Broad Cookie Domain",
                    "The cookie '" + cookieName + "' is scoped to a broad domain ('" + domain + "'). This exposes the cookie to all subdomains, increasing the risk of interception or theft via vulnerable subdomains.",
                    RiskLevel.LOW,
                    Vulnerability.Confidence.MEDIUM,
                    operation,
                    CWEReference.CWE_200, // Or similar
                    List.of("CAPEC-31"),
                    3.1,
                    "Cookie sets Domain=" + domain,
                    "Scope cookies to specific hostnames rather than broad wildcard domains where possible.", operation, null,
                                    "API Endpoint (Network)",
                                    "Unauthorized Access / Data Exposure"));
            }
        }
    }

    private String extractAttribute(String cookie, String attributeName) {
        String[] parts = cookie.split(";");
        for (String part : parts) {
            String trimmed = part.trim();
            if (trimmed.toLowerCase().startsWith(attributeName.toLowerCase() + "=")) {
                return trimmed.substring(attributeName.length() + 1);
            }
        }
        return null;
    }
}

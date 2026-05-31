package ch.hug.orthrusdast.scanner;


import ch.hug.orthrusdast.http.ScanHttpClient;
import ch.hug.orthrusdast.model.CWEReference;
import ch.hug.orthrusdast.model.Operation;
import ch.hug.orthrusdast.model.RiskLevel;
import ch.hug.orthrusdast.model.Vulnerability;
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

    private void checkCookie(String cookie, Operation operation, List<Vulnerability> vulns, ch.hug.orthrusdast.http.ScanHttpResponse response) {
        String lowerCookie = cookie.toLowerCase();
        String cookieName = cookie.split("=")[0].trim();

        if (!lowerCookie.contains("secure")) {
            vulns.add(Vulnerability.createWithDetails(
                    "Missing 'Secure' Cookie Attribute",
                    "The cookie '" + cookieName + "' is missing the 'Secure' attribute. This means the cookie could be transmitted in cleartext over unencrypted HTTP connections.",
                    RiskLevel.MEDIUM,
                    Vulnerability.Confidence.HIGH,
                    getId(),
                    operation,
                    CWEReference.CWE_614,
                    List.of("CAPEC-31"),
                    5.3,
                    "Set-Cookie header found without 'Secure' flag: " + cookie,
                    "Always set the 'Secure' flag for sensitive cookies so they are only transmitted over HTTPS.",
                    "Sent standard " + operation.method() + " request.",
                    "Status: " + response.statusCode() + "\nReceived Set-Cookie header: " + cookie + "\nBody snippet: " + (response.body() != null && response.body().length() > 200 ? response.body().substring(0, 200) + "..." : String.valueOf(response.body()))
            ,
                                    "API Endpoint (Network)",
                                    "Unauthorized Access / Data Exposure"));
        }

        if (!lowerCookie.contains("httponly")) {
            vulns.add(Vulnerability.createWithDetails(
                    "Missing 'HttpOnly' Cookie Attribute",
                    "The cookie '" + cookieName + "' is missing the 'HttpOnly' attribute. This exposes the cookie to Cross-Site Scripting (XSS) attacks, allowing client-side scripts to read its value.",
                    RiskLevel.MEDIUM,
                    Vulnerability.Confidence.HIGH,
                    getId(),
                    operation,
                    CWEReference.CWE_1004,
                    List.of("CAPEC-31"),
                    5.3,
                    "Set-Cookie header found without 'HttpOnly' flag: " + cookie,
                    "Always set the 'HttpOnly' flag for session identifiers and sensitive cookies to prevent access from JavaScript.",
                    "Sent standard " + operation.method() + " request.",
                    "Status: " + response.statusCode() + "\nReceived Set-Cookie header: " + cookie + "\nBody snippet: " + (response.body() != null && response.body().length() > 200 ? response.body().substring(0, 200) + "..." : String.valueOf(response.body()))
            ,
                                    "API Endpoint (Network)",
                                    "Unauthorized Access / Data Exposure"));
        }

        if (!lowerCookie.contains("samesite")) {
            vulns.add(Vulnerability.createWithDetails(
                    "Missing 'SameSite' Cookie Attribute",
                    "The cookie '" + cookieName + "' is missing the 'SameSite' attribute. This increases the risk of Cross-Site Request Forgery (CSRF) attacks.",
                    RiskLevel.LOW,
                    Vulnerability.Confidence.HIGH,
                    getId(),
                    operation,
                    CWEReference.CWE_1275,
                    List.of("CAPEC-62"),
                    4.3,
                    "Set-Cookie header found without 'SameSite' attribute: " + cookie,
                    "Configure the cookie with 'SameSite=Lax' or 'SameSite=Strict' to restrict cross-site sharing.",
                    "Sent standard " + operation.method() + " request.",
                    "Status: " + response.statusCode() + "\nReceived Set-Cookie header: " + cookie + "\nBody snippet: " + (response.body() != null && response.body().length() > 200 ? response.body().substring(0, 200) + "..." : String.valueOf(response.body()))
            ,
                                    "API Endpoint (Network)",
                                    "Unauthorized Access / Data Exposure"));
        }
    }
}

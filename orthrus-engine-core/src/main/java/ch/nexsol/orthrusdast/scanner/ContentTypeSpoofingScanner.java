package ch.nexsol.orthrusdast.scanner;

import java.util.List;

import java.util.HashMap;
import java.util.Map;

import ch.nexsol.orthrusdast.http.ScanHttpClient;
import ch.nexsol.orthrusdast.model.CWEReference;
import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.RiskLevel;
import ch.nexsol.orthrusdast.model.Vulnerability;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;

/**
 * Scans for Content-Type Spoofing / Misconfiguration (API8:2023).
 */
@Component
public class ContentTypeSpoofingScanner implements SecurityScanner {

    private final ScanHttpClient httpClient;
    // XML payload targeting XXE or simple parser failures
    private static final String XML_PAYLOAD = "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>";

    public ContentTypeSpoofingScanner(ScanHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public String getId() {
        return "content-type-spoofing";
    }

    @Override
    public String getName() {
        return "Content-Type Spoofing Scanner";
    }

    @Override
    public Flux<Vulnerability> scan(Operation operation) {
        String method = operation.method().toUpperCase();
        if (!("POST".equals(method) || "PUT".equals(method) || "PATCH".equals(method))) {
            return Flux.empty();
        }
        
        Map<String, String> headers = new HashMap<>();
        if (operation.headers() != null) {
            headers.putAll(operation.headers());
        }
        
        Flux<Vulnerability> xxeVulns = Flux.empty();
        Flux<Vulnerability> bypassVulns = Flux.empty();

        // 1. Spoof Content-Type to XML with XXE Payload
        Map<String, String> xmlHeaders = new HashMap<>(headers);
        xmlHeaders.put("Content-Type", "application/xml");
        Operation testOpXml = new Operation(
                operation.url(), operation.method(), xmlHeaders, operation.queryParams(),
                XML_PAYLOAD, operation.securityRequirements(), operation.expectedContentTypes(), operation.authScheme()
        );

        xxeVulns = httpClient.send(testOpXml).flatMapMany(response -> {
            if (response.bodyContainsExact("root:x:0:0")) {
                Vulnerability vuln = createVulnerabilityWithTrace(
                        "XML External Entity (XXE) via Content-Type Spoofing",
                        "The endpoint blindly accepted an XML payload despite expecting JSON, and is vulnerable to XML External Entity (XXE) injection.",
                        RiskLevel.CRITICAL, Vulnerability.Confidence.HIGH, operation, CWEReference.CWE_611, List.of("CAPEC-228"), 7.5,
                        "Server successfully parsed XML and executed the external entity to read /etc/passwd.",
                        "Strictly enforce expected Content-Types (e.g. drop non-JSON requests). Disable external entities in XML parsers if XML must be supported.", testOpXml, response,
                        "API Endpoint (Network)", "Unauthorized Access / Data Exposure");
                return Flux.just(vuln);
            }
            if (response.statusCode().is5xxServerError()) {
                Vulnerability vuln = createVulnerabilityWithTrace(
                        "Unhandled Exception on Unexpected Content-Type",
                        "The endpoint throws a 500 Server Error when provided with an unexpected Content-Type.",
                        RiskLevel.LOW, Vulnerability.Confidence.HIGH, operation, CWEReference.CWE_209, List.of("CAPEC-228"), 3.5,
                        "Server returned 500 Internal Server Error when receiving application/xml.",
                        "Reject unsupported Content-Types explicitly with a 415 Unsupported Media Type response.", testOpXml, response,
                        "API Endpoint (Network)", "Unauthorized Access / Data Exposure");
                return Flux.just(vuln);
            }
            return Flux.empty();
        });

        // 2. WAF Bypass: Send original body (if present) with text/plain
        if (operation.body() != null && !operation.body().isEmpty()) {
            Map<String, String> textHeaders = new HashMap<>(headers);
            textHeaders.put("Content-Type", "text/plain");
            Operation testOpText = new Operation(
                    operation.url(), operation.method(), textHeaders, operation.queryParams(),
                    operation.body(), operation.securityRequirements(), operation.expectedContentTypes(), operation.authScheme()
            );

            bypassVulns = httpClient.send(operation).flatMapMany(originalResponse -> 
                httpClient.send(testOpText).flatMapMany(testResponse -> {
                    if (originalResponse.isSuccessful() && testResponse.isSuccessful() && originalResponse.statusCode().equals(testResponse.statusCode())) {
                        // If sending text/plain succeeds just like application/json, it might bypass WAFs looking for JSON
                        Vulnerability vuln = createVulnerabilityWithTrace(
                            "Content-Type Spoofing (WAF Bypass Vector)",
                            "The endpoint accepts requests with Content-Type 'text/plain' and parses the body successfully anyway. This can be used to bypass WAF rules.",
                            RiskLevel.LOW, Vulnerability.Confidence.MEDIUM, operation, CWEReference.CWE_434, List.of("CAPEC-228"), 4.3,
                            "Server responded with " + testResponse.statusCode() + " for both application/json and text/plain.",
                            "Strictly enforce 'Content-Type: application/json' and reject (415 Unsupported Media Type) any other content types.", testOpText, testResponse,
                            "API Endpoint (Network)", "Unauthorized Access / Data Exposure");
                        return Flux.just(vuln);
                    }
                    return Flux.empty();
                })
            );
        }

        return Flux.concat(xxeVulns, bypassVulns);
    }
    
    private String truncate(String text) {
        if (text == null) return "null";
        return text.length() > 200 ? text.substring(0, 200) + "..." : text;
    }
}

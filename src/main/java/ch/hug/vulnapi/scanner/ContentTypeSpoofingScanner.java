package ch.hug.vulnapi.scanner;
import java.util.List;

import ch.hug.vulnapi.http.ScanHttpClient;
import ch.hug.vulnapi.model.CWEReference;
import ch.hug.vulnapi.model.Operation;
import ch.hug.vulnapi.model.RiskLevel;
import ch.hug.vulnapi.model.Vulnerability;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;

import java.util.HashMap;
import java.util.Map;

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
        
        // Spoof Content-Type to XML
        headers.put("Content-Type", "application/xml");

        Operation testOp = new Operation(
                operation.url(),
                operation.method(),
                headers,
                operation.queryParams(),
                XML_PAYLOAD,
                operation.securityRequirements(),
                operation.expectedContentTypes(),
                operation.authScheme()
        );

        return httpClient.send(testOp)
                .flatMapMany(response -> {
                    // Check for XXE
                    if (response.bodyContainsExact("root:x:0:0")) {
                        Vulnerability vuln = Vulnerability.createWithDetails(
                                "XML External Entity (XXE) via Content-Type Spoofing",
                                "The endpoint blindly accepted an XML payload despite expecting JSON, and is vulnerable to XML External Entity (XXE) injection.",
                                RiskLevel.CRITICAL,
                                Vulnerability.Confidence.HIGH,
                                getId(),
                                operation,
                                CWEReference.CWE_611,
                                "Security Misconfiguration",
                                List.of("CAPEC-228"),
                                7.5,
                                "Server successfully parsed XML and executed the external entity to read /etc/passwd.",
                                "Strictly enforce expected Content-Types (e.g. drop non-JSON requests). Disable external entities in XML parsers if XML must be supported.",
                                "Spoofed Content-Type to application/xml and sent XML with XXE payload.",
                                "Status: " + response.statusCode() + "\nBody snippet: " + truncate(response.body())
                        );
                        return Flux.just(vuln);
                    }
                    // Check if it causes a 7.5 error (unhandled parser exception)
                    if (response.statusCode().is5xxServerError()) {
                        Vulnerability vuln = Vulnerability.createWithDetails(
                                "Unhandled Exception on Unexpected Content-Type",
                                "The endpoint throws a 7.5 Server Error when provided with an unexpected Content-Type.",
                                RiskLevel.LOW,
                                Vulnerability.Confidence.HIGH,
                                getId(),
                                operation,
                                CWEReference.CWE_209,
                                "Security Misconfiguration",
                                List.of("CAPEC-228"),
                                7.5,
                                "Server returned 7.5 Internal Server Error when receiving application/xml.",
                                "Reject unsupported Content-Types explicitly with a 415 Unsupported Media Type response.",
                                "Spoofed Content-Type to application/xml.",
                                "Status: " + response.statusCode()
                        );
                        return Flux.just(vuln);
                    }
                    return Flux.empty();
                });
    }
    
    private String truncate(String text) {
        if (text == null) return "null";
        return text.length() > 200 ? text.substring(0, 200) + "..." : text;
    }
}

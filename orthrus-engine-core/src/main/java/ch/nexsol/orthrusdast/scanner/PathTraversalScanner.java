package ch.nexsol.orthrusdast.scanner;

import java.util.List;

import ch.nexsol.orthrusdast.http.ScanHttpClient;
import ch.nexsol.orthrusdast.model.CWEReference;
import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.RiskLevel;
import ch.nexsol.orthrusdast.model.Vulnerability;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;

import java.util.HashMap;
import java.util.Map;
import java.util.List;

/**
 * Scans for Path Traversal / Directory Traversal vulnerabilities (CWE-22).
 */
@Component
public class PathTraversalScanner implements SecurityScanner {

    private static final Logger log = LoggerFactory.getLogger(PathTraversalScanner.class);
    private final ScanHttpClient httpClient;
    
    private static final String PAYLOAD = "../../../../../../../../../../../../etc/passwd";
    private static final String WINDOWS_PAYLOAD = "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini";

    public PathTraversalScanner(ScanHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public String getId() {
        return "path-traversal";
    }

    @Override
    public String getName() {
        return "Path Traversal Scanner";
    }

    @Override
    public Flux<Vulnerability> scan(Operation operation) {
        List<String> payloads = List.of(
            "../../../../../../../../../../../../etc/passwd",
            "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%2fpasswd",
            "../../../../../../../../../../../../etc/passwd%00.png"
        );

        return Flux.fromIterable(payloads).concatMap(payload -> {
            return InjectionHelper.generateInjectedOperations(operation, payload).concatMap(test -> 
                httpClient.send(test.mutatedOperation()).flatMapMany(response -> {
                    boolean linuxVuln = response.bodyContains("root:x:0:0");
                    boolean windowsVuln = response.bodyContains("[extensions]") || response.bodyContains("[fonts]");

                    if (linuxVuln || windowsVuln) {
                         Vulnerability vuln = createVulnerabilityWithTrace(
                            "Path Traversal (LFI)",
                            "The endpoint allows an attacker to read arbitrary files on the server filesystem.",
                            RiskLevel.CRITICAL,
                            Vulnerability.Confidence.HIGH,
                            operation,
                            CWEReference.CWE_22,
                            List.of("CAPEC-126"),
                            7.5,
                            "Response contains contents of a sensitive OS file when injecting " + payload + " into " + test.injectionPoint() + ".",
                            "Validate input against an allowlist. Avoid passing raw user input to filesystem APIs. Use path canonicalization and verify the target path is within the expected directory.", test.mutatedOperation(), response,
                            "API Endpoint (Network)",
                            "Unauthorized Access / Data Exposure");
                        return Flux.just(vuln);
                    }
                    return Flux.empty();
                })
            );
        });
    }

    private String truncate(String text) {
        if (text == null) return "null";
        return text.length() > 200 ? text.substring(0, 200) + "..." : text;
    }
}

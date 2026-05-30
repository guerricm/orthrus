package ch.hug.vulnapi.scanner;
import java.util.List;

import ch.hug.vulnapi.http.ScanHttpClient;
import ch.hug.vulnapi.model.CWEReference;
import ch.hug.vulnapi.model.Operation;
import ch.hug.vulnapi.model.RiskLevel;
import ch.hug.vulnapi.model.Vulnerability;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;

import java.util.HashMap;
import java.util.Map;

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
        if (operation.queryParams() != null && !operation.queryParams().isEmpty()) {
            return Flux.fromIterable(operation.queryParams().keySet())
                    .flatMap(paramName -> testParam(operation, paramName, PAYLOAD).switchIfEmpty(testParam(operation, paramName, WINDOWS_PAYLOAD)));
        }
        return Flux.empty();
    }
    
    private Flux<Vulnerability> testParam(Operation operation, String paramName, String payload) {
        Map<String, String> modifiedParams = new HashMap<>(operation.queryParams());
        modifiedParams.put(paramName, payload);
        
        Operation testOp = new Operation(
                operation.url(),
                operation.method(),
                operation.headers(),
                modifiedParams,
                operation.body(),
                operation.securityRequirements(),
                operation.expectedContentTypes(),
                operation.authScheme()
        );
        
        return httpClient.send(testOp)
                .flatMapMany(response -> {
                    boolean linuxVuln = payload.equals(PAYLOAD) && response.bodyContainsExact("root:x:0:0");
                    boolean windowsVuln = payload.equals(WINDOWS_PAYLOAD) && (response.bodyContainsExact("[extensions]") || response.bodyContainsExact("[fonts]"));

                    if (linuxVuln || windowsVuln) {
                         Vulnerability vuln = Vulnerability.createWithDetails(
                            "Path Traversal",
                            "The endpoint allows an attacker to read arbitrary files on the server filesystem.",
                            RiskLevel.CRITICAL,
                            Vulnerability.Confidence.HIGH,
                            getId(),
                            operation,
                            CWEReference.CWE_22,
                            "Broken Access Control",
                                List.of("CAPEC-126"),
                                7.5,
                            "Response contains contents of a sensitive OS file when payload '" + payload + "' was injected.",
                            "Validate input against an allowlist. Avoid passing raw user input to filesystem APIs. Use path canonicalization and verify the target path is within the expected directory.",
                            "Injected payload into query param: " + paramName + "=" + payload,
                            "Status: " + response.statusCode() + "\nBody snippet: " + truncate(response.body())
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

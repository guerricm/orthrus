package ch.hug.orthrusdast.scanner;

import java.util.List;

import ch.hug.orthrusdast.http.ScanHttpClient;
import ch.hug.orthrusdast.model.CWEReference;
import ch.hug.orthrusdast.model.Operation;
import ch.hug.orthrusdast.model.RiskLevel;
import ch.hug.orthrusdast.model.Vulnerability;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;

import java.util.HashMap;
import java.util.Map;

/**
 * Scans for Open Redirect vulnerabilities (CWE-601).
 */
@Component
public class OpenRedirectScanner implements SecurityScanner {

    private final ScanHttpClient httpClient;
    private static final String MALICIOUS_URL = "http://evil-attacker.com";

    public OpenRedirectScanner(ScanHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public String getId() {
        return "open-redirect";
    }

    @Override
    public String getName() {
        return "Open Redirect Scanner";
    }

    @Override
    public Flux<Vulnerability> scan(Operation operation) {
        if (operation.queryParams() != null && !operation.queryParams().isEmpty()) {
            return Flux.fromIterable(operation.queryParams().keySet())
                    .filter(this::isPotentialRedirectParam)
                    .flatMap(paramName -> testParam(operation, paramName));
        }
        return Flux.empty();
    }
    
    private boolean isPotentialRedirectParam(String paramName) {
        String lower = paramName.toLowerCase();
        return lower.contains("redirect") || lower.contains("url") || lower.contains("return") 
            || lower.contains("next") || lower.contains("goto") || lower.contains("target");
    }

    private Flux<Vulnerability> testParam(Operation operation, String paramName) {
        Map<String, String> modifiedParams = new HashMap<>(operation.queryParams());
        modifiedParams.put(paramName, MALICIOUS_URL);
        
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
                    // Check if the response is a 3xx redirect AND the Location header matches the malicious URL
                    if (response.statusCode().is3xxRedirection()) {
                        String locationHeader = response.getHeader("Location");
                        if (locationHeader != null && locationHeader.startsWith(MALICIOUS_URL)) {
                             Vulnerability vuln = Vulnerability.createWithDetails(
                                "Open Redirect",
                                "The endpoint accepts user-controlled input to determine the target of an HTTP redirect.",
                                RiskLevel.MEDIUM,
                                Vulnerability.Confidence.HIGH,
                                getId(),
                                operation,
                                CWEReference.CWE_601,
                                List.of("CAPEC-116"),
                                6.1,
                                "Server responded with a redirect to the injected malicious URL.",
                                "Do not allow users to specify redirect destinations directly. If necessary, use an allowlist or an indirect reference (like an ID mapped to a URL on the server).",
                                "Injected payload into query param: " + paramName + "=" + MALICIOUS_URL,
                                "Status: " + response.statusCode() + "\nLocation Header: " + locationHeader
                            ,
                                    "API Endpoint (Network)",
                                    "Unauthorized Access / Data Exposure");
                            return Flux.just(vuln);
                        }
                    }
                    return Flux.empty();
                });
    }
}

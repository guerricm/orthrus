package ch.hug.vulnapi.scanner;

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
 * Scans for Server-Side Template Injection (SSTI) (CWE-1336).
 */
@Component
public class SstiScanner implements SecurityScanner {

    private final ScanHttpClient httpClient;
    
    // Testing mathematical evaluation which is standard for SSTI
    private static final String PAYLOAD_1 = "{{7*7}}";
    private static final String PAYLOAD_2 = "${7*7}";
    private static final String EXPECTED_RESULT = "49";

    public SstiScanner(ScanHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public String getId() {
        return "ssti";
    }

    @Override
    public String getName() {
        return "Server-Side Template Injection Scanner";
    }

    @Override
    public Flux<Vulnerability> scan(Operation operation) {
        if (operation.queryParams() != null && !operation.queryParams().isEmpty()) {
            return Flux.fromIterable(operation.queryParams().keySet())
                    .flatMap(paramName -> testParam(operation, paramName, PAYLOAD_1).switchIfEmpty(testParam(operation, paramName, PAYLOAD_2)));
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
                    // Check if the evaluated math expression (49) is in the response, BUT the original payload is not.
                    // If the payload is reflected as is, it's not SSTI.
                    if (response.bodyContainsExact(EXPECTED_RESULT) && !response.bodyContainsExact(payload)) {
                        
                        Vulnerability vuln = Vulnerability.createWithDetails(
                            "Server-Side Template Injection (SSTI)",
                            "The endpoint evaluates user input as template code, allowing arbitrary code execution on the server.",
                            RiskLevel.CRITICAL,
                            Vulnerability.Confidence.HIGH,
                            getId(),
                            operation,
                            CWEReference.CWE_1336,
                            "Injection",
                            "Response contains the evaluated result ('49') of the injected template expression '" + payload + "'.",
                            "Do not concatenate user input directly into templates. Use logic-less templates or securely pass input as context variables instead of template strings.",
                            "Injected template payload into query param: " + paramName + "=" + payload,
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

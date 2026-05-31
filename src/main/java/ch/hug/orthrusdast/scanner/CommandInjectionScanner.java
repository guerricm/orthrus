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
 * Scans for OS Command Injection vulnerabilities (CWE-78).
 */
@Component
public class CommandInjectionScanner implements SecurityScanner {

    private final ScanHttpClient httpClient;
    
    // Using an arithmetic evaluation payload to prevent false positives from simple string reflection.
    // If the application simply echoes the input, the response will contain "$((837492+561837))".
    // If the application is truly vulnerable, the shell will evaluate the arithmetic and output "1399329".
    private static final String CALC_PAYLOAD_CONTENT = "$((837492+561837))";
    private static final String CALC_RESULT = "1399329";
    private static final String[] PAYLOADS = {
        "; echo " + CALC_PAYLOAD_CONTENT,
        "| echo " + CALC_PAYLOAD_CONTENT,
        "& echo " + CALC_PAYLOAD_CONTENT,
        "$(echo " + CALC_PAYLOAD_CONTENT + ")",
        "`echo " + CALC_PAYLOAD_CONTENT + "`"
    };

    public CommandInjectionScanner(ScanHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public String getId() {
        return "cmd-injection";
    }

    @Override
    public String getName() {
        return "OS Command Injection Scanner";
    }

    @Override
    public Flux<Vulnerability> scan(Operation operation) {
        if (operation.queryParams() != null && !operation.queryParams().isEmpty()) {
            return Flux.fromIterable(operation.queryParams().keySet())
                    .flatMap(paramName -> testParam(operation, paramName));
        }
        return Flux.empty();
    }
    
    private Flux<Vulnerability> testParam(Operation operation, String paramName) {
        return Flux.fromArray(PAYLOADS)
                .flatMap(payload -> {
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
                                if (response.bodyContainsExact(CALC_RESULT) && !response.bodyContainsExact(CALC_PAYLOAD_CONTENT)) {
                                     Vulnerability vuln = Vulnerability.createWithDetails(
                                        "OS Command Injection",
                                        "The endpoint appears vulnerable to OS Command Injection in parameter '" + paramName + "'.",
                                        RiskLevel.CRITICAL,
                                        Vulnerability.Confidence.HIGH,
                                        getId(),
                                        operation,
                                        CWEReference.CWE_78,
                                        "Injection",
                                        List.of("CAPEC-88"),
                                        9.8,
                                        "Response contains the evaluated arithmetic result '" + CALC_RESULT + "' from the injected payload, indicating the OS command was executed.",
                                        "Avoid invoking OS commands directly. If necessary, use built-in language APIs and strictly sanitize and parameterize all input.",
                                        "Injected payload into query param: " + paramName + "=" + payload,
                                        "Status: " + response.statusCode() + "\nBody snippet: " + truncate(response.body())
                                    );
                                    return Flux.just(vuln);
                                }
                                return Flux.empty();
                            });
                }).take(1); // Stop after finding the first working payload for a parameter to avoid spamming
    }

    private String truncate(String text) {
        if (text == null) return "null";
        return text.length() > 200 ? text.substring(0, 200) + "..." : text;
    }
}

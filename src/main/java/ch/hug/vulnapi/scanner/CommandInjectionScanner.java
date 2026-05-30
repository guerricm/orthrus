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
 * Scans for OS Command Injection vulnerabilities (CWE-78).
 */
@Component
public class CommandInjectionScanner implements SecurityScanner {

    private final ScanHttpClient httpClient;
    
    // Using a payload that echoes a specific string, which is highly unlikely to appear randomly
    private static final String ECHO_MARKER = "VULNAPI_CMD_INJECT_SUCCESS";
    private static final String[] PAYLOADS = {
        "; echo " + ECHO_MARKER,
        "| echo " + ECHO_MARKER,
        "& echo " + ECHO_MARKER,
        "$(echo " + ECHO_MARKER + ")",
        "`echo " + ECHO_MARKER + "`"
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
                                if (response.bodyContainsExact(ECHO_MARKER)) {
                                     Vulnerability vuln = Vulnerability.createWithDetails(
                                        "OS Command Injection",
                                        "The endpoint appears vulnerable to OS Command Injection in parameter '" + paramName + "'.",
                                        RiskLevel.CRITICAL,
                                        Vulnerability.Confidence.HIGH,
                                        getId(),
                                        operation,
                                        CWEReference.CWE_78,
                                        "Injection",
                                        "Response contains the injected marker string '" + ECHO_MARKER + "', indicating the OS command was executed and its output was returned.",
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

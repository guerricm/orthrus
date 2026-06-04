package ch.nexsol.orthrusdast.scanner;


import ch.nexsol.orthrusdast.http.ScanHttpClient;
import ch.nexsol.orthrusdast.model.CWEReference;
import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.RiskLevel;
import ch.nexsol.orthrusdast.model.Vulnerability;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;

import java.util.List;
import java.util.Map;

/**
 * Scans for Code Injection / Eval Injection (CWE-94).
 */
@Component
public class CodeInjectionScanner implements SecurityScanner {

    private final ScanHttpClient httpClient;
    
    // Payloads designed to trigger a specific mathematical or string operation if evaluated as code.
    // We expect the evaluated result ("999999") to appear in the response.
    // The exact string "999999" is excluded from the payloads to prevent false positives from simple input reflection.
    private static final Map<String, String> PAYLOADS = Map.of(
            "PHP Eval", "echo 999900+99;",
            "Node.js Eval", "require('child_process').execSync('expr 999900 + 99').toString()",
            "Python Exec", "__import__('os').popen('expr 999900 + 99').read()"
    );

    public CodeInjectionScanner(ScanHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public String getId() {
        return "code-injection";
    }

    @Override
    public String getName() {
        return "Code Injection Scanner";
    }

    @Override
    public Flux<Vulnerability> scan(Operation operation) {
        if (!List.of("GET", "POST", "PUT").contains(operation.method().toUpperCase())) {
            return Flux.empty();
        }

        return Flux.fromIterable(PAYLOADS.entrySet()).concatMap(entry -> {
            String payloadName = entry.getKey();
            String payload = entry.getValue();

            return InjectionHelper.generateInjectedOperations(operation, payload)
                    .concatMap(test -> {
                        return httpClient.send(test.mutatedOperation()).flatMapMany(response -> {
                            // If the math expression was evaluated, the result will be in the response
                            if (response.bodyContains("999999") && !response.bodyContains(payload)) {
                                Vulnerability vuln = createVulnerabilityWithTrace(
                                        "Code Injection (" + payloadName + ")",
                                        "The endpoint evaluates untrusted input as executable code in " + test.injectionPoint() + ".",
                                        RiskLevel.CRITICAL,
                                        Vulnerability.Confidence.HIGH,
                                        operation,
                                        CWEReference.CWE_94,
                                        List.of("CAPEC-35", "CAPEC-242"),
                                        9.8,
                                        "The payload was evaluated and the result '999999' was found in the response.",
                                        "Never pass untrusted data directly to eval() or similar dynamic execution functions. Use safe parsers and avoid dynamic code execution entirely.", test.mutatedOperation(), response,
                                                "API Endpoint (Network)",
                                                "Unauthorized Access / Data Exposure");
                                return Flux.just(vuln);
                            }
                            return Flux.empty();
                        });
                    });
        });
    }
}

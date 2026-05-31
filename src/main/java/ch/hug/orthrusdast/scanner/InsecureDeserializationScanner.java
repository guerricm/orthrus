package ch.hug.orthrusdast.scanner;

import ch.hug.orthrusdast.http.ScanHttpClient;
import ch.hug.orthrusdast.model.CWEReference;
import ch.hug.orthrusdast.model.Operation;
import ch.hug.orthrusdast.model.RiskLevel;
import ch.hug.orthrusdast.model.Vulnerability;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;

import java.util.List;
import java.util.Map;

/**
 * Scans for Insecure Deserialization vulnerabilities by sending known magic bytes or serialized payloads.
 */
@Component
public class InsecureDeserializationScanner implements SecurityScanner {

    private final ScanHttpClient httpClient;

    // Common magic payloads that cause predictable errors if deserialized
    private static final Map<String, String> PAYLOADS = Map.of(
            "Java Serialized (Hex encoded header)", "rO0ABXNyAA...",
            "Python Pickle", "c__builtin__\neval\n(Vprint(1)\ntR.",
            "Jackson/Fastjson Gadget", "{\"@type\":\"java.lang.Class\",\"val\":\"com.sun.rowset.JdbcRowSetImpl\"}"
    );

    public InsecureDeserializationScanner(ScanHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public String getId() {
        return "insecure-deserialization";
    }

    @Override
    public String getName() {
        return "Insecure Deserialization Scanner";
    }

    @Override
    public Flux<Vulnerability> scan(Operation operation) {
        if (!List.of("POST", "PUT", "PATCH").contains(operation.method().toUpperCase())) {
            return Flux.empty();
        }

        return Flux.fromIterable(PAYLOADS.entrySet()).flatMap(entry -> {
            String payloadName = entry.getKey();
            String payload = entry.getValue();

            Operation testOp = new Operation(
                    operation.url(),
                    operation.method(),
                    operation.headers(),
                    operation.queryParams(),
                    payload,
                    operation.securityRequirements(),
                    operation.expectedContentTypes(),
                    operation.authScheme()
            );

            return httpClient.send(testOp).flatMapMany(response -> {
                // If the server returns a 500 or stack trace containing deserialization errors, flag it
                if (response.statusCode().is5xxServerError() && 
                    (response.bodyContains("java.io.ObjectInputStream") || 
                     response.bodyContains("ClassCastException") ||
                     response.bodyContains("cPickle") ||
                     response.bodyContains("fastjson"))) {
                    
                    Vulnerability vuln = Vulnerability.createWithDetails(
                            "Insecure Deserialization",
                            "The endpoint appears to blindly deserialize the request body. Sending a " + payloadName + " payload triggered a deserialization error.",
                            RiskLevel.CRITICAL,
                            Vulnerability.Confidence.MEDIUM,
                            getId(),
                            operation,
                            CWEReference.CWE_502,
                            "Injection",
                            List.of("CAPEC-586"),
                            9.8,
                            "Server responded with a stack trace indicating deserialization failure.",
                            "Avoid deserializing untrusted data. If necessary, use safe formats like standard JSON, or use strict type whitelisting.",
                            "Injected payload: " + payload,
                            "Status: " + response.statusCode() + "\nBody snippet: " + (response.body() != null && response.body().length() > 200 ? response.body().substring(0, 200) + "..." : String.valueOf(response.body()))
                    );
                    return Flux.just(vuln);
                }
                return Flux.empty();
            });
        });
    }
}

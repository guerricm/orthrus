package ch.nexsol.orthrusdast.scanner;


import ch.nexsol.orthrusdast.http.ScanHttpClient;
import ch.nexsol.orthrusdast.model.CWEReference;
import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.RiskLevel;
import ch.nexsol.orthrusdast.model.Vulnerability;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Scans for Sensitive Information Exposure in Query Strings (CWE-598).
 */
@Component
public class SensitiveQueryScanner implements SecurityScanner {

    private final ScanHttpClient httpClient;
    private final ObjectMapper mapper = new ObjectMapper();
    
    private static final List<String> SENSITIVE_KEYWORDS = List.of(
            "password", "pwd", "token", "secret", "apikey", "api_key", "auth", "session", "credential"
    );

    public SensitiveQueryScanner(ScanHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public String getId() {
        return "sensitive-query-params";
    }

    @Override
    public String getName() {
        return "Sensitive Query Parameters Scanner";
    }

    @Override
    public Flux<Vulnerability> scan(Operation operation) {
        return Flux.defer(() -> {
        Flux<Vulnerability> passiveVulns = Flux.empty();
        Flux<Vulnerability> activeVulns = Flux.empty();

        if ("GET".equals(operation.method().toUpperCase())) {
            // Passive check: Check if any query parameter name matches a sensitive keyword
            for (String paramName : operation.queryParams().keySet()) {
                String lowerParam = paramName.toLowerCase();
                for (String keyword : SENSITIVE_KEYWORDS) {
                    if (lowerParam.contains(keyword)) {
                        Vulnerability vuln = createVulnerabilityWithTrace(
                                "Sensitive Information in Query String (Passive)",
                                "The endpoint accepts a parameter named '" + paramName + "' in the URL query string. Query strings are logged by reverse proxies, web servers, and browser histories, leading to sensitive data exposure.",
                                RiskLevel.MEDIUM,
                                Vulnerability.Confidence.HIGH,
                                operation,
                                CWEReference.CWE_598,
                                List.of("CAPEC-87"),
                                6.5,
                                "Parameter '" + paramName + "' found in GET request.",
                                "Move sensitive data from the query string to HTTP Headers (e.g., Authorization header) or the request body (e.g., POST request).", operation, null,
                                        "API Endpoint (Network)",
                                        "Unauthorized Access / Data Exposure");
                        passiveVulns = Flux.just(vuln);
                        break;
                    }
                }
            }
        } else if (List.of("POST", "PUT", "PATCH").contains(operation.method().toUpperCase())) {
            // Active check: Try moving JSON body fields to Query String (Parameter Binding abuse)
            if (operation.body() != null && operation.body().trim().startsWith("{")) {
                try {
                    Map<String, Object> bodyMap = mapper.readValue(operation.body(), new TypeReference<Map<String, Object>>() {});
                    
                    // Only test if body has sensitive keywords
                    boolean hasSensitiveField = bodyMap.keySet().stream().anyMatch(k -> SENSITIVE_KEYWORDS.stream().anyMatch(k.toLowerCase()::contains));
                    
                    if (hasSensitiveField) {
                        Map<String, String> newQueryParams = new HashMap<>(operation.queryParams());
                        for (Map.Entry<String, Object> entry : bodyMap.entrySet()) {
                            newQueryParams.put(entry.getKey(), String.valueOf(entry.getValue()));
                        }
                        
                        Operation testOp = new Operation(
                                operation.url(), operation.method(), operation.headers(), newQueryParams,
                                "{}", operation.securityRequirements(), operation.expectedContentTypes(), operation.authScheme()
                        );
                        
                        activeVulns = httpClient.send(testOp).flatMapMany(response -> {
                            if (response.isSuccessful()) {
                                Vulnerability vuln = createVulnerabilityWithTrace(
                                        "Sensitive Parameter Binding in Query String (Active)",
                                        "The endpoint accepts POST/PUT body parameters via the URL Query String. This can lead to sensitive data exposure in server logs if clients or attackers pass credentials in the URL.",
                                        RiskLevel.MEDIUM,
                                        Vulnerability.Confidence.MEDIUM,
                                        operation,
                                        CWEReference.CWE_598,
                                        List.of("CAPEC-87"),
                                        6.5,
                                        "Server responded with " + response.statusCode() + " OK after moving JSON body parameters to the Query String.",
                                        "Explicitly define parameter binding sources (e.g. @RequestBody in Spring) and reject requests that pass sensitive fields in the query string.", testOp, response,
                                        "API Endpoint (Network)",
                                        "Unauthorized Access / Data Exposure");
                                return Flux.just(vuln);
                            }
                            return Flux.empty();
                        });
                    }
                } catch (Exception e) {
                    // Ignore parse errors
                }
            }
        }

        return Flux.concat(passiveVulns, activeVulns);
        });
    }
}

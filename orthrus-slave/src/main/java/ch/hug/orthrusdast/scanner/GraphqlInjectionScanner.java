package ch.hug.orthrusdast.scanner;

import ch.hug.orthrusdast.http.ScanHttpClient;
import ch.hug.orthrusdast.model.CWEReference;
import ch.hug.orthrusdast.model.Operation;
import ch.hug.orthrusdast.model.RiskLevel;
import ch.hug.orthrusdast.model.Vulnerability;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Scans GraphQL Operations for Injection Vulnerabilities (SQLi, XSS, CmdInj)
 * by injecting payloads into GraphQL variables.
 */
@Component
public class GraphqlInjectionScanner implements SecurityScanner {

    private static final Logger log = LoggerFactory.getLogger(GraphqlInjectionScanner.class);
    private final ScanHttpClient httpClient;
    private final ObjectMapper objectMapper = new ObjectMapper();

    private static final List<PayloadDef> PAYLOADS = List.of(
            new PayloadDef("SQL Injection", "' OR '1'='1", CWEReference.CWE_89, RiskLevel.HIGH, List.of("CAPEC-66"),
                    9.8),
            new PayloadDef("SQL Injection", "1; DROP TABLE users", CWEReference.CWE_89, RiskLevel.HIGH,
                    List.of("CAPEC-66"), 9.8),
            new PayloadDef("Cross-Site Scripting (XSS)", "<script>alert(1)</script>", CWEReference.CWE_79,
                    RiskLevel.HIGH, List.of("CAPEC-63"), 8.2),
            new PayloadDef("Command Injection", "; cat /etc/passwd", CWEReference.CWE_78, RiskLevel.HIGH,
                    List.of("CAPEC-88"), 9.8));

    public GraphqlInjectionScanner(ScanHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public String getId() {
        return "graphql-injection";
    }

    @Override
    public String getName() {
        return "GraphQL Injection Scanner";
    }

    @Override
    public Flux<Vulnerability> scan(Operation operation) {
        if (!"POST".equalsIgnoreCase(operation.method()) || operation.body() == null
                || !operation.body().contains("\"variables\"")) {
            return Flux.empty();
        }

        try {
            Map<String, Object> bodyMap = objectMapper.readValue(operation.body(),
                    new TypeReference<Map<String, Object>>() {
                    });
            if (!bodyMap.containsKey("variables") || !(bodyMap.get("variables") instanceof Map)) {
                return Flux.empty();
            }

            @SuppressWarnings("unchecked")
            Map<String, Object> variables = (Map<String, Object>) bodyMap.get("variables");

            return Flux.fromIterable(variables.keySet())
                    .flatMap(varName -> Flux.fromIterable(PAYLOADS)
                            .flatMap(payloadDef -> testVariable(operation, bodyMap, variables, varName, payloadDef)));

        } catch (Exception e) {
            log.warn("Failed to parse GraphQL body for injection scanning: {}", e.getMessage());
            return Flux.empty();
        }
    }

    private Flux<Vulnerability> testVariable(Operation operation, Map<String, Object> originalBodyMap,
            Map<String, Object> originalVariables, String varName, PayloadDef payloadDef) {

        try {
            // Clone the maps to avoid modifying the original
            Map<String, Object> modifiedVariables = new HashMap<>(originalVariables);
            modifiedVariables.put(varName, payloadDef.payload);

            Map<String, Object> modifiedBodyMap = new HashMap<>(originalBodyMap);
            modifiedBodyMap.put("variables", modifiedVariables);

            String newBody = objectMapper.writeValueAsString(modifiedBodyMap);

            Operation testOp = new Operation(
                    operation.url(),
                    operation.method(),
                    operation.headers(),
                    operation.queryParams(),
                    newBody,
                    operation.securityRequirements(),
                    operation.expectedContentTypes(),
                    operation.authScheme());

            return httpClient.send(testOp)
                    .flatMapMany(response -> {
                        String body = response.body() != null ? response.body().toLowerCase() : "";
                        boolean isVulnerable = false;

                        if (payloadDef.cwe == CWEReference.CWE_89 && (body.contains("syntax error")
                                || body.contains("mysql_fetch") || body.contains("ora-"))) {
                            isVulnerable = true;
                        } else if (payloadDef.cwe == CWEReference.CWE_79
                                && body.contains(payloadDef.payload.toLowerCase())) {
                            isVulnerable = true;
                        } else if (payloadDef.cwe == CWEReference.CWE_78
                                && (body.contains("root:x:0:0") || body.contains("command not found"))) {
                            isVulnerable = true;
                        }

                        if (isVulnerable) {
                            Vulnerability vuln = createVulnerabilityWithTrace(
                                    "Potential " + payloadDef.name + " in GraphQL Variable",
                                    "The endpoint might be vulnerable to " + payloadDef.name + " via the '" + varName
                                            + "' variable.",
                                    payloadDef.risk,
                                    Vulnerability.Confidence.MEDIUM,
                                    operation,
                                    payloadDef.cwe,
                                    payloadDef.capec,
                                    payloadDef.cvss,
                                    "Response indicates a potential injection vulnerability when payload '"
                                            + payloadDef.payload + "' was supplied.",
                                    "Validate and sanitize all GraphQL variable inputs. Use parameterized queries for databases.", testOp, response,
                                    "API Endpoint (Network)",
                                    "Unauthorized Access / Data Exposure");
                            return Flux.just(vuln);
                        }
                        return Flux.empty();
                    });
        } catch (Exception e) {
            return Flux.empty();
        }
    }

    private String truncate(String text) {
        if (text == null)
            return "null";
        return text.length() > 200 ? text.substring(0, 200) + "..." : text;
    }

    private record PayloadDef(String name, String payload, CWEReference cwe, RiskLevel risk, List<String> capec,
            double cvss) {
    }
}

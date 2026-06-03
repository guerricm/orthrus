package ch.hug.orthrusdast.scanner;

import java.util.List;

import ch.hug.orthrusdast.http.ScanHttpClient;
import ch.hug.orthrusdast.model.CWEReference;
import ch.hug.orthrusdast.model.Operation;
import ch.hug.orthrusdast.model.RiskLevel;
import ch.hug.orthrusdast.model.Vulnerability;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;

/**
 * Scans for Mass Assignment / BOPLA (API3:2023) (CWE-915).
 */
@Component
public class MassAssignmentScanner implements SecurityScanner {

    private static final Logger log = LoggerFactory.getLogger(MassAssignmentScanner.class);
    private final ScanHttpClient httpClient;
    private final ObjectMapper mapper = new ObjectMapper();

    public MassAssignmentScanner(ScanHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public String getId() {
        return "mass-assignment";
    }

    @Override
    public String getName() {
        return "Mass Assignment Scanner (BOPLA)";
    }

    @Override
    public Flux<Vulnerability> scan(Operation operation) {
        String method = operation.method().toUpperCase();
        if (!("POST".equals(method) || "PUT".equals(method) || "PATCH".equals(method))) {
            return Flux.empty();
        }

        if (operation.body() == null || operation.body().isEmpty() || !operation.body().trim().startsWith("{")) {
            return Flux.empty();
        }

        try {
            ObjectNode jsonBody = (ObjectNode) mapper.readTree(operation.body());
            // Inject common privilege escalation fields
            jsonBody.put("is_admin", true);
            jsonBody.put("isAdmin", true);
            jsonBody.put("role", "admin");
            jsonBody.put("permissions", "all");
            
            String modifiedBody = mapper.writeValueAsString(jsonBody);

            Operation testOp = new Operation(
                    operation.url(),
                    operation.method(),
                    operation.headers(),
                    operation.queryParams(),
                    modifiedBody,
                    operation.securityRequirements(),
                    operation.expectedContentTypes(),
                    operation.authScheme()
            );

            return httpClient.send(testOp)
                    .flatMapMany(response -> {
                        // If the server accepts the modified payload without a 400 Bad Request, it MIGHT be vulnerable
                        if (response.isSuccessful()) {
                            Vulnerability vuln = createVulnerabilityWithTrace(
                                    "Potential Mass Assignment (BOPLA)",
                                    "The endpoint accepts unexpected fields (e.g., 'is_admin', 'role') in the JSON payload without returning a validation error.",
                                    RiskLevel.MEDIUM,
                                    Vulnerability.Confidence.LOW,
                                    operation,
                                    CWEReference.CWE_915,
                                    List.of("CAPEC-17"),
                                6.5,
                                    "Server returned " + response.statusCode() + " OK after injecting privilege escalation fields into the JSON payload.",
                                    "Use DTOs (Data Transfer Objects) to explicitly map accepted fields. Avoid binding HTTP requests directly to domain models or database entities.", testOp, response,
                                    "API Endpoint (Network)",
                                    "Unauthorized Access / Data Exposure");
                            return Flux.just(vuln);
                        }
                        return Flux.empty();
                    });
        } catch (Exception e) {
            log.debug("Failed to parse or modify JSON body for {}: {}", operation.url(), e.getMessage());
            return Flux.empty();
        }
    }
}

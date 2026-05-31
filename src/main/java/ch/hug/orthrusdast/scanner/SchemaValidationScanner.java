package ch.hug.orthrusdast.scanner;

import ch.hug.orthrusdast.http.ScanHttpClient;
import ch.hug.orthrusdast.model.CWEReference;
import ch.hug.orthrusdast.model.Operation;
import ch.hug.orthrusdast.model.RiskLevel;
import ch.hug.orthrusdast.model.Vulnerability;
import io.swagger.v3.oas.models.media.Schema;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.HashMap;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Scans for Improper Input Validation (CWE-20) by testing OpenAPI schema constraints.
 * It verifies if the API actually enforces required fields, max lengths, and data types.
 */
@Component
@SuppressWarnings("rawtypes")
public class SchemaValidationScanner implements SecurityScanner {

    private final ScanHttpClient httpClient;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public SchemaValidationScanner(ScanHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public String getId() {
        return "schema-validation";
    }

    @Override
    public String getName() {
        return "Schema Validation Scanner";
    }

    @Override
    public Flux<Vulnerability> scan(Operation operation) {
        if (!List.of("POST", "PUT", "PATCH").contains(operation.method().toUpperCase())) {
            return Flux.empty();
        }

        // Check if we have access to the original OpenAPI Operation node
        if (!(operation.sourceNode() instanceof io.swagger.v3.oas.models.Operation openApiOperation)) {
            return Flux.empty();
        }

        if (openApiOperation.getRequestBody() == null || openApiOperation.getRequestBody().getContent() == null) {
            return Flux.empty();
        }

        io.swagger.v3.oas.models.media.MediaType mediaType = openApiOperation.getRequestBody().getContent().get("application/json");
        if (mediaType == null || mediaType.getSchema() == null) {
            return Flux.empty();
        }

        Schema schema = mediaType.getSchema();
        if (schema.getProperties() == null) {
            return Flux.empty();
        }

        List<Flux<Vulnerability>> scans = new ArrayList<>();

        // Generate baseline valid payload
        Map<String, Object> baseline = buildBaseline(schema);
        Map<String, Schema> properties = schema.getProperties();

        for (Map.Entry<String, Schema> entry : properties.entrySet()) {
            String propName = entry.getKey();
            Schema propSchema = entry.getValue();

            // Test 1: Missing required property
            if (schema.getRequired() != null && schema.getRequired().contains(propName)) {
                Map<String, Object> mutated = new HashMap<>(baseline);
                mutated.remove(propName);
                scans.add(testPayload(operation, mutated, "Missing Required Property", 
                    "The property '" + propName + "' is required by the OpenAPI schema, but omitting it did not result in a 400 Bad Request error.", propName));
            }

            // Test 2: Max Length violation (String)
            if ("string".equals(propSchema.getType()) && propSchema.getMaxLength() != null) {
                Map<String, Object> mutated = new HashMap<>(baseline);
                int maxLength = propSchema.getMaxLength();
                mutated.put(propName, "A".repeat(maxLength + 10)); // overflow
                scans.add(testPayload(operation, mutated, "Max Length Constraint Violation", 
                    "The property '" + propName + "' has a maxLength of " + maxLength + " defined in the schema, but providing a longer string did not result in a 400 Bad Request error.", propName));
            }

            // Test 3: Type Mismatch (String instead of Integer)
            if ("integer".equals(propSchema.getType()) || "number".equals(propSchema.getType())) {
                Map<String, Object> mutated = new HashMap<>(baseline);
                mutated.put(propName, "invalid_string_instead_of_number");
                scans.add(testPayload(operation, mutated, "Type Constraint Violation", 
                    "The property '" + propName + "' expects a number according to the schema, but providing a string did not result in a 400 Bad Request error.", propName));
            }
        }

        return Flux.merge(scans);
    }

    private Map<String, Object> buildBaseline(Schema schema) {
        Map<String, Object> result = new HashMap<>();
        Map<String, Schema> properties = schema.getProperties();
        if (properties != null) {
            for (Map.Entry<String, Schema> entry : properties.entrySet()) {
                result.put(entry.getKey(), getDummyValue(entry.getValue()));
            }
        }
        return result;
    }

    private Object getDummyValue(Schema propSchema) {
        if ("integer".equals(propSchema.getType()) || "number".equals(propSchema.getType())) {
            return 42;
        } else if ("boolean".equals(propSchema.getType())) {
            return true;
        } else if ("array".equals(propSchema.getType())) {
            return List.of("test");
        }
        return "valid_string";
    }

    private Flux<Vulnerability> testPayload(Operation operation, Map<String, Object> payloadMap, String testName, String description, String propName) {
        String payloadJson;
        try {
            payloadJson = objectMapper.writeValueAsString(payloadMap);
        } catch (Exception e) {
            return Flux.empty();
        }

        Operation testOp = new Operation(
                operation.url(),
                operation.method(),
                operation.headers(),
                operation.queryParams(),
                payloadJson,
                operation.securityRequirements(),
                operation.expectedContentTypes(),
                operation.authScheme(),
                operation.templateUrl(),
                operation.sourceNode()
        );

        return httpClient.send(testOp).flatMapMany(response -> {
            // A well-implemented API should return 4xx (Client Error) for schema violations.
            // If it returns 2xx (Success) or 5xx (Server Crash), it indicates improper input validation.
            if (response.statusCode().is2xxSuccessful() || response.statusCode().is5xxServerError()) {
                Vulnerability vuln = Vulnerability.createWithDetails(
                        "Improper Input Validation (" + testName + ")",
                        description,
                        RiskLevel.MEDIUM,
                        Vulnerability.Confidence.HIGH,
                        getId(),
                        operation,
                        CWEReference.CWE_20,
                        "Validation",
                        List.of("CAPEC-3"),
                        5.3,
                        "The server responded with " + response.statusCode() + " instead of enforcing the schema constraint (should be 400).",
                        "Ensure that all incoming data is strictly validated against the defined OpenAPI schema constraints (types, lengths, required fields) using a validation middleware before processing.",
                        "Sent payload violating schema constraint on property: " + propName + "\nPayload: " + payloadJson,
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

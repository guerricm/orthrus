package ch.nexsol.orthrusdast.scanner;

import java.util.List;

import ch.nexsol.orthrusdast.http.ScanHttpClient;
import ch.nexsol.orthrusdast.model.CWEReference;
import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.RiskLevel;
import ch.nexsol.orthrusdast.model.Vulnerability;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.UUID;

/**
 * Scans for Broken Object Level Authorization (BOLA) / IDOR.
 */
@Component
public class BolaScanner implements SecurityScanner {

    private final ScanHttpClient httpClient;
    private static final Pattern ID_PATTERN = Pattern.compile("/([0-9]+)(/|$)");

    public BolaScanner(ScanHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public String getId() {
        return "bola";
    }

    @Override
    public String getName() {
        return "Broken Object Level Authorization (BOLA) Scanner";
    }

    @Override
    public Flux<Vulnerability> scan(Operation operation) {
        Flux<Vulnerability> pathBola = testPathBola(operation);
        Flux<Vulnerability> queryBola = testQueryBola(operation);
        
        return Flux.concat(pathBola, queryBola);
    }

    private Flux<Vulnerability> testPathBola(Operation operation) {
        Matcher matcher = ID_PATTERN.matcher(operation.url());
        if (!matcher.find()) {
            return Flux.empty(); 
        }

        String originalIdStr = matcher.group(1);
        long originalId;
        try {
            originalId = Long.parseLong(originalIdStr);
        } catch (NumberFormatException e) {
            return Flux.empty();
        }

        // Test with ID + 1, ID - 1, and UUID
        return Flux.just(String.valueOf(originalId + 1), 
                         String.valueOf(originalId - 1 > 0 ? originalId - 1 : originalId + 2), 
                         UUID.randomUUID().toString())
                .concatMap(testId -> testBolaId(operation, originalIdStr, testId, "URL path"));
    }

    private Flux<Vulnerability> testQueryBola(Operation operation) {
        if (operation.queryParams() == null || operation.queryParams().isEmpty()) {
            return Flux.empty();
        }

        return Flux.fromIterable(operation.queryParams().entrySet())
                .filter(entry -> entry.getKey().toLowerCase().contains("id"))
                .concatMap(entry -> {
                    String paramName = entry.getKey();
                    String originalValue = entry.getValue();

                    // Test 1: HPP (HTTP Parameter Pollution) - Add array-like suffix to param
                    Map<String, String> hppParams = new HashMap<>(operation.queryParams());
                    hppParams.remove(paramName);
                    // Standard Maps don't easily allow duplicate keys, so we simulate array/HPP in the key name or value
                    // For typical frameworks: ?id=1&id=2 is often parsed as an array, or the last value wins
                    // We can simulate by appending a raw string to the URL if we had control, but via Operation we must use Map.
                    // Let's test array wrapping instead: ?id[]=1&id[]=2
                    hppParams.put(paramName + "[]", originalValue);
                    hppParams.put(paramName, "99999999"); // Fake ID

                    Operation hppOp = new Operation(
                            operation.url(), operation.method(), operation.headers(), hppParams,
                            operation.body(), operation.securityRequirements(), operation.expectedContentTypes(), operation.authScheme()
                    );

                    // Test 2: UUID substitution
                    Map<String, String> uuidParams = new HashMap<>(operation.queryParams());
                    uuidParams.put(paramName, UUID.randomUUID().toString());
                    Operation uuidOp = new Operation(
                            operation.url(), operation.method(), operation.headers(), uuidParams,
                            operation.body(), operation.securityRequirements(), operation.expectedContentTypes(), operation.authScheme()
                    );

                    return Flux.concat(
                            executeBolaCheck(hppOp, operation, "HPP/Array wrapping in Query param '" + paramName + "'", originalValue, "99999999"),
                            executeBolaCheck(uuidOp, operation, "UUID substitution in Query param '" + paramName + "'", originalValue, "UUID")
                    );
                });
    }

    private Flux<Vulnerability> testBolaId(Operation operation, String originalId, String testId, String location) {
        String newUrl = operation.url().replaceFirst("/" + originalId + "(/|$)", "/" + testId + "$1");

        Operation testOp = new Operation(
                newUrl, operation.method(), operation.headers(), operation.queryParams(),
                operation.body(), operation.securityRequirements(), operation.expectedContentTypes(), operation.authScheme()
        );

        return executeBolaCheck(testOp, operation, location, originalId, testId);
    }

    private Flux<Vulnerability> executeBolaCheck(Operation testOp, Operation originalOp, String location, String originalId, String testId) {
        return httpClient.send(testOp)
                .flatMapMany(response -> {
                    // If the response is 200 OK and contains data (not just an empty array/object/error),
                    // it MIGHT be a BOLA vulnerability or a type-confusion bug
                    if (response.isSuccessful() && response.body() != null && response.body().length() > 20 && !response.bodyContains("error") && !response.bodyContains("not found")) {
                        Vulnerability vuln = createVulnerabilityWithTrace(
                                "Potential Broken Object Level Authorization (BOLA)",
                                "The endpoint returned a successful response when the resource ID was modified in " + location + " from " + originalId + " to " + testId + ". Ensure the authenticated user has permission to access this specific object.",
                                RiskLevel.MEDIUM,
                                Vulnerability.Confidence.LOW,
                                originalOp,
                                CWEReference.CWE_639,
                                List.of("CAPEC-17"),
                                7.5,
                                "Response status " + response.statusCode() + " when accessing ID " + testId,
                                "Implement strict authorization checks at the object level. Verify the user requesting the data owns or has roles to access it. Validate data types (e.g. UUIDs vs Ints).", testOp, response,
                                    "API Endpoint (Network)",
                                    "Unauthorized Access / Data Exposure");
                        return Flux.just(vuln);
                    }
                    return Flux.empty();
                });
    }
}

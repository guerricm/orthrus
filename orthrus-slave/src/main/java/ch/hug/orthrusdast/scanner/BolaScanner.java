package ch.hug.orthrusdast.scanner;

import java.util.List;

import ch.hug.orthrusdast.http.ScanHttpClient;
import ch.hug.orthrusdast.model.CWEReference;
import ch.hug.orthrusdast.model.Operation;
import ch.hug.orthrusdast.model.RiskLevel;
import ch.hug.orthrusdast.model.Vulnerability;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
        // Look for sequential IDs in the URL path, e.g., /users/123 or /orders/456/items
        Matcher matcher = ID_PATTERN.matcher(operation.url());
        if (!matcher.find()) {
            return Flux.empty(); // No obvious numeric ID found
        }

        String originalIdStr = matcher.group(1);
        long originalId;
        try {
            originalId = Long.parseLong(originalIdStr);
        } catch (NumberFormatException e) {
            return Flux.empty();
        }

        // Test with ID + 1 and ID - 1
        return Flux.just(originalId + 1, originalId - 1 > 0 ? originalId - 1 : originalId + 2)
                .flatMap(testId -> testBolaId(operation, originalIdStr, String.valueOf(testId)));
    }

    private Flux<Vulnerability> testBolaId(Operation operation, String originalId, String testId) {
        String newUrl = operation.url().replaceFirst("/" + originalId + "(/|$)", "/" + testId + "$1");

        Operation testOp = new Operation(
                newUrl,
                operation.method(),
                operation.headers(),
                operation.queryParams(),
                operation.body(), // Note: Ideally we'd replace IDs in the body too
                operation.securityRequirements(),
                operation.expectedContentTypes(),
                operation.authScheme()
        );

        return httpClient.send(testOp)
                .flatMapMany(response -> {
                    // If the response is 200 OK and contains data (not just an empty array/object),
                    // it MIGHT be a BOLA vulnerability if the user isn't supposed to access it.
                    // This is a high-false-positive check without knowing the data ownership context.
                    if (response.isSuccessful() && response.body() != null && response.body().length() > 10) {
                        Vulnerability vuln = createVulnerabilityWithTrace(
                                "Potential Broken Object Level Authorization (BOLA)",
                                "The endpoint returned a successful response when the resource ID was modified from " + originalId + " to " + testId + ". Ensure the authenticated user has permission to access this specific object.",
                                RiskLevel.MEDIUM,
                                Vulnerability.Confidence.LOW,
                                operation, // Pass the original operation to preserve templateUrl
                                CWEReference.CWE_639,
                                List.of("CAPEC-17"),
                                7.5,
                                "Response status " + response.statusCode() + " when accessing ID " + testId,
                                "Implement strict authorization checks at the object level. Verify the user requesting the data owns or has roles to access it.", testOp, response,
                                    "API Endpoint (Network)",
                                    "Unauthorized Access / Data Exposure");
                        return Flux.just(vuln);
                    }
                    return Flux.empty();
                });
    }
}

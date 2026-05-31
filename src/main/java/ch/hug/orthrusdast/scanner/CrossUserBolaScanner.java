package ch.hug.orthrusdast.scanner;

import java.util.List;

import ch.hug.orthrusdast.http.ScanHttpClient;
import ch.hug.orthrusdast.model.CWEReference;
import ch.hug.orthrusdast.model.Operation;
import ch.hug.orthrusdast.model.RiskLevel;
import ch.hug.orthrusdast.model.ScanConfiguration;
import ch.hug.orthrusdast.model.Vulnerability;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;

/**
 * Advanced BOLA Scanner that uses a secondary user token to test cross-user data access.
 */
@Component
public class CrossUserBolaScanner implements SecurityScanner {

    private static final Logger log = LoggerFactory.getLogger(CrossUserBolaScanner.class);
    private final ScanHttpClient httpClient;

    public CrossUserBolaScanner(ScanHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public String getId() {
        return "cross-user-bola";
    }

    @Override
    public String getName() {
        return "Cross-User BOLA Scanner";
    }

    @Override
    public Flux<Vulnerability> scan(Operation operation) {
        // Fallback if not called with config, do nothing
        return Flux.empty();
    }

    @Override
    public Flux<Vulnerability> scan(Operation operation, ScanConfiguration config) {
        // Only run if a secondary auth scheme is provided
        if (config.secondaryAuthScheme() == null) {
            log.debug("Skipping CrossUserBolaScanner because no secondary auth scheme is configured.");
            return Flux.empty();
        }

        // We assume the endpoints discovered by the engine are accessible by the primary user.
        // We will replay the exact same request using User B's token.
        Operation crossUserOp = new Operation(
                operation.url(),
                operation.method(),
                operation.headers(),
                operation.queryParams(),
                operation.body(),
                operation.securityRequirements(),
                operation.expectedContentTypes(),
                config.secondaryAuthScheme() // Inject User B's token!
        );

        return httpClient.send(crossUserOp)
                .flatMapMany(response -> {
                    // If User B gets a successful response with data, it's highly suspicious (potential BOLA)
                    if (response.isSuccessful() && response.body() != null && response.body().length() > 10) {
                        Vulnerability vuln = Vulnerability.createWithDetails(
                                "Cross-User Broken Object Level Authorization (BOLA)",
                                "The endpoint returned a successful response when accessed with a secondary user's token. If this resource contains private data belonging to the primary user, this is a critical BOLA vulnerability.",
                                RiskLevel.HIGH,
                                Vulnerability.Confidence.MEDIUM, // Medium because the resource *might* just be public/shared
                                getId(),
                                operation,
                                CWEReference.CWE_639,
                                List.of("CAPEC-17"),
                                7.5,
                                "Server returned " + response.statusCode() + " OK when requesting User A's resource using User B's authentication token.",
                                "Verify ownership of the requested resource. Ensure the authenticated user has explicit permission to access this specific object ID.",
                                "Replayed exact request but swapped Authorization header with secondary user's token.",
                                "Status: " + response.statusCode() + "\nBody snippet: " + truncate(response.body())
                        ,
                                    "API Endpoint (Network)",
                                    "Unauthorized Access / Data Exposure");
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

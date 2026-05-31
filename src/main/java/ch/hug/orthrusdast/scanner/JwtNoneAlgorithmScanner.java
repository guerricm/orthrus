package ch.hug.orthrusdast.scanner;

import java.util.List;

import ch.hug.orthrusdast.http.ScanHttpClient;
import ch.hug.orthrusdast.model.CWEReference;
import ch.hug.orthrusdast.model.Operation;
import ch.hug.orthrusdast.model.RiskLevel;
import ch.hug.orthrusdast.model.Vulnerability;
import ch.hug.orthrusdast.model.SecurityScheme;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import java.util.Map;
import java.util.HashMap;
import java.util.Base64;

/**
 * Scans for JWT "none" algorithm vulnerabilities.
 */
@Component
public class JwtNoneAlgorithmScanner implements SecurityScanner {

    private static final Logger log = LoggerFactory.getLogger(JwtNoneAlgorithmScanner.class);
    private final ScanHttpClient httpClient;

    public JwtNoneAlgorithmScanner(ScanHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public String getId() {
        return "jwt-none-alg";
    }

    @Override
    public String getName() {
        return "JWT 'none' Algorithm Scanner";
    }

    @Override
    public Flux<Vulnerability> scan(Operation operation) {
        if (operation.authScheme() == null || operation.authScheme().type() != SecurityScheme.AuthType.BEARER) {
            return Flux.empty();
        }

        String originalToken = operation.authScheme().value();
        String[] parts = originalToken.split("\\.");
        if (parts.length != 3) {
            return Flux.empty(); // Not a standard JWT
        }

        // Create a JWT with 'none' alg
        String header = "{\"alg\":\"none\",\"typ\":\"JWT\"}";
        String encodedHeader = Base64.getUrlEncoder().withoutPadding().encodeToString(header.getBytes());
        String noneAlgToken = encodedHeader + "." + parts[1] + "."; // No signature

        SecurityScheme noneScheme = SecurityScheme.bearer(noneAlgToken);
        Operation testOp = operation.withAuth(noneScheme);

        return httpClient.send(testOp)
                .flatMapMany(response -> {
                    if (response.isSuccessful()) {
                        Vulnerability vuln = Vulnerability.createWithDetails(
                                "JWT 'none' Algorithm Accepted",
                                "The endpoint accepts JWTs signed with the 'none' algorithm, allowing authentication bypass.",
                                RiskLevel.CRITICAL,
                                Vulnerability.Confidence.HIGH,
                                getId(),
                                operation,
                                CWEReference.CWE_287,
                                List.of("CAPEC-115"),
                                9.8,
                                "Endpoint returned " + response.statusCode() + " OK when a JWT with 'alg: none' was provided.",
                                "Configure your JWT library to explicitly reject the 'none' algorithm and enforce expected algorithms.",
                                "Sent JWT: " + noneAlgToken,
                                "Status: " + response.statusCode()
                        ,
                                    "API Endpoint (Network)",
                                    "Unauthorized Access / Data Exposure");
                        return Flux.just(vuln);
                    }
                    return Flux.empty();
                });
    }
}

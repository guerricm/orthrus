package ch.nexsol.orthrusdast.scanner;

import java.util.List;

import ch.nexsol.orthrusdast.http.ScanHttpClient;
import ch.nexsol.orthrusdast.model.CWEReference;
import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.RiskLevel;
import ch.nexsol.orthrusdast.model.Vulnerability;
import ch.nexsol.orthrusdast.model.SecurityScheme;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import javax.crypto.SecretKey;

/**
 * Scans for JWTs signed with a blank (empty) secret or common weak secrets.
 */
@Component
public class JwtBlankSecretScanner implements SecurityScanner {

    private static final Logger log = LoggerFactory.getLogger(JwtBlankSecretScanner.class);
    private static final List<String> WEAK_SECRETS = List.of("", "secret", "password", "123456", "admin", "test", "qwerty");
    private final ScanHttpClient httpClient;

    public JwtBlankSecretScanner(ScanHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public String getId() {
        return "jwt-blank-secret";
    }

    @Override
    public String getName() {
        return "JWT Blank Secret Scanner";
    }

    @Override
    public Flux<Vulnerability> scan(Operation operation) {
        if (operation.authScheme() == null || operation.authScheme().type() != SecurityScheme.AuthType.BEARER) {
            return Flux.empty();
        }

        String originalToken = operation.authScheme().value();
        String[] parts = originalToken.split("\\.");
        if (parts.length != 3) {
            return Flux.empty();
        }

        String headerAndPayload = parts[0] + "." + parts[1];

        return Flux.fromIterable(WEAK_SECRETS)
                .concatMap(secret -> {
                    try {
                        javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
                        mac.init(new javax.crypto.spec.SecretKeySpec(secret.getBytes(), "HmacSHA256"));
                        byte[] signatureBytes = mac.doFinal(headerAndPayload.getBytes());
                        String signature = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(signatureBytes);
                        
                        String forgedToken = headerAndPayload + "." + signature;
                        SecurityScheme forgedScheme = SecurityScheme.bearer(forgedToken);
                        Operation testOp = operation.withAuth(forgedScheme);

                        return httpClient.send(testOp)
                                .flatMapMany(response -> {
                                    if (response.isSuccessful() && !response.bodyContains("Unauthorized") && !response.bodyContains("Unauthenticated") && !response.bodyContains("invalid token")) {
                                        String title = secret.isEmpty() ? "JWT Blank Secret Accepted" : "JWT Weak Secret Accepted";
                                        String description = secret.isEmpty() ? "The endpoint accepts JWTs signed with a blank (empty) secret." : "The endpoint accepts JWTs signed with a weak secret: '" + secret + "'.";
                                        
                                        Vulnerability vuln = createVulnerabilityWithTrace(
                                                title,
                                                description,
                                                RiskLevel.CRITICAL,
                                                Vulnerability.Confidence.HIGH,
                                                operation,
                                                CWEReference.CWE_287,
                                                List.of("CAPEC-115"),
                                                9.8,
                                                "Endpoint returned " + response.statusCode() + " OK when a forged JWT was provided.",
                                                "Ensure your JWT secret is strong, randomly generated (at least 256 bits), and securely stored. Never use empty or default secrets.", testOp, response,
                                                "API Endpoint (Network)",
                                                "Unauthorized Access / Data Exposure");
                                        return Flux.just(vuln);
                                    }
                                    return Flux.empty();
                                });
                    } catch (Exception e) {
                        return Flux.empty();
                    }
                }).take(1); // Stop after finding the first weak secret that works
    }
}

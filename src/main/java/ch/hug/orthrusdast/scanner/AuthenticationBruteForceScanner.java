package ch.hug.orthrusdast.scanner;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ch.hug.orthrusdast.http.ScanHttpClient;
import ch.hug.orthrusdast.model.CWEReference;
import ch.hug.orthrusdast.model.Operation;
import ch.hug.orthrusdast.model.RiskLevel;
import ch.hug.orthrusdast.model.Vulnerability;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;

/**
 * Scans authentication endpoints for susceptibility to brute force / weak passwords.
 * (CWE-307, CWE-521).
 */
@Component
public class AuthenticationBruteForceScanner implements SecurityScanner {

    private static final Logger log = LoggerFactory.getLogger(AuthenticationBruteForceScanner.class);
    private final ScanHttpClient httpClient;
    
    // List of extremely common weak passwords to test
    private final List<String> weakPasswords;

    // Regex to match JSON password fields like "password": "...", "pwd": "...", "pass": "..."
    private static final Pattern PASSWORD_JSON_PATTERN = Pattern.compile("(\"(?:password|pwd|pass)\"\\s*:\\s*\")[^\"]*(\")", Pattern.CASE_INSENSITIVE);

    public AuthenticationBruteForceScanner(ScanHttpClient httpClient) {
        this.httpClient = httpClient;
        this.weakPasswords = loadPasswords();
    }
    
    private List<String> loadPasswords() {
        List<String> passwords = new ArrayList<>();
        try {
            ClassPathResource resource = new ClassPathResource("passwords.txt");
            if (resource.exists()) {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(resource.getInputStream(), StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        String pw = line.trim();
                        if (!pw.isEmpty()) {
                            passwords.add(pw);
                        }
                    }
                }
                log.info("Loaded {} passwords for brute force scanning", passwords.size());
            } else {
                log.warn("passwords.txt not found on classpath, using minimal fallback list");
                passwords.addAll(List.of("123456", "password", "admin", "root", "qwerty"));
            }
        } catch (Exception e) {
            log.error("Failed to load passwords.txt", e);
            passwords.addAll(List.of("123456", "password", "admin", "root", "qwerty"));
        }
        return passwords;
    }

    @Override
    public String getId() {
        return "auth-bruteforce";
    }

    @Override
    public String getName() {
        return "Authentication Brute Force Scanner";
    }

    @Override
    public Flux<Vulnerability> scan(Operation operation) {
        String urlLower = operation.url().toLowerCase();
        boolean isAuthEndpoint = urlLower.contains("/login") || urlLower.contains("/auth") 
                              || urlLower.contains("/token") || urlLower.contains("/signin");

        if (!isAuthEndpoint || !"POST".equalsIgnoreCase(operation.method()) || operation.body() == null) {
            return Flux.empty();
        }
        
        Matcher matcher = PASSWORD_JSON_PATTERN.matcher(operation.body());
        if (!matcher.find()) {
            // We couldn't identify a password field in the JSON body, or it's not JSON
            return Flux.empty();
        }

        log.debug("Scanning for Brute Force / Weak Passwords on: {}", operation.url());

        return Flux.fromIterable(weakPasswords)
                .flatMap(weakPassword -> {
                    // Replace the original password with the weak password
                    String modifiedBody = matcher.replaceAll("$1" + weakPassword + "$2");
                    
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
                                // If we get a 200 OK with a weak password, it's a huge vulnerability
                                if (response.statusCode().is2xxSuccessful()) {
                                    Vulnerability vuln = Vulnerability.createWithDetails(
                                            "Weak Password Acceptance (Brute Force)",
                                            "The authentication endpoint accepted a very common weak password ('" + weakPassword + "').",
                                            RiskLevel.CRITICAL,
                                            Vulnerability.Confidence.HIGH,
                                            getId(),
                                            operation,
                                            CWEReference.CWE_521,
                                            "Broken Authentication",
                                            List.of("CAPEC-112"),
                                            9.8,
                                            "Endpoint returned " + response.statusCode() + " OK when authenticating with the weak password '" + weakPassword + "'.",
                                            "Implement strict password complexity requirements and rate limiting or account lockout mechanisms to prevent brute forcing.",
                                            "Sent POST request with password field replaced by '" + weakPassword + "'.",
                                            "Status: " + response.statusCode() + "\nBody snippet: " + truncate(response.body())
                                    );
                                    return Flux.just(vuln);
                                }
                                return Flux.empty();
                            });
                });
    }

    private String truncate(String text) {
        if (text == null) return "null";
        return text.length() > 200 ? text.substring(0, 200) + "..." : text;
    }
}

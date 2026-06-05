package ch.nexsol.orthrusdast.scanner;

import java.util.List;
import java.util.Map;
import java.net.URI;
import java.net.URISyntaxException;

import ch.nexsol.orthrusdast.http.ScanHttpClient;
import ch.nexsol.orthrusdast.model.CWEReference;
import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.RiskLevel;
import ch.nexsol.orthrusdast.model.Vulnerability;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;

/**
 * Scans for CORS misconfigurations (CWE-346, CWE-942).
 */
@Component
public class CorsScanner implements SecurityScanner {

    private final ScanHttpClient httpClient;
    private static final String MALICIOUS_ORIGIN = "https://evil-attacker.com";

    public CorsScanner(ScanHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public String getId() {
        return "cors";
    }

    @Override
    public String getName() {
        return "CORS Misconfiguration Scanner";
    }

    @Override
    public Flux<Vulnerability> scan(Operation operation) {
        return Flux.defer(() -> {
        String targetHost = "target.com";
        try {
            URI uri = new URI(operation.url());
            targetHost = uri.getHost();
            if (targetHost == null) targetHost = "target.com";
        } catch (URISyntaxException e) {
            // default
        }

        List<String> payloads = List.of(
            "https://evil-attacker.com",
            "null",
            "https://" + targetHost + ".evil.com",
            "https://evil" + targetHost
        );

        return Flux.fromIterable(payloads).concatMap(origin -> 
            httpClient.sendRaw(operation.url(), "OPTIONS", Map.of(
                    "Origin", origin,
                    "Access-Control-Request-Method", operation.method()
            ), null).flatMapMany(response -> {
                String acao = response.getHeader("Access-Control-Allow-Origin");
                String acac = response.getHeader("Access-Control-Allow-Credentials");

                boolean isVulnerable = false;
                String evidence = "";

                if (origin.equals(acao)) {
                    isVulnerable = true;
                    evidence = "Server reflected the requested Origin ('" + origin + "') in Access-Control-Allow-Origin.";
                    if ("true".equals(acac)) {
                        evidence += " It also allows credentials (Access-Control-Allow-Credentials: true), which is critical.";
                    }
                } else if ("*".equals(acao) && "true".equals(acac)) {
                    // Browsers usually block * with credentials, but it's a severe misconfig
                    isVulnerable = true;
                    evidence = "Server returned Access-Control-Allow-Origin: * along with Access-Control-Allow-Credentials: true.";
                }

                if (isVulnerable) {
                    RiskLevel level = ("true".equals(acac) && !origin.equals("null")) ? RiskLevel.HIGH : RiskLevel.MEDIUM;
                    Vulnerability vuln = createVulnerabilityWithTrace(
                            "CORS Misconfiguration - Bypass",
                            "The endpoint has overly permissive Cross-Origin Resource Sharing (CORS) settings, allowing a bypass using origin: " + origin,
                            level,
                            Vulnerability.Confidence.HIGH,
                            operation,
                            CWEReference.CWE_942,
                            List.of("CAPEC-63"),
                            5.3,
                            evidence,
                            "Restrict Access-Control-Allow-Origin to trusted domains only. Do not reflect the Origin header blindly. Use strict string matching (not startsWith or endsWith).", operation, null,
                                        "API Endpoint (Network)",
                                        "Unauthorized Access / Data Exposure");
                    return Flux.just(vuln);
                }

                return Flux.empty();
            })
        ).take(1); // Stop after finding one bypass
            });
    }
}

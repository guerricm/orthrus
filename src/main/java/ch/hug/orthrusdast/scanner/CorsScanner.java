package ch.hug.orthrusdast.scanner;

import java.util.List;

import ch.hug.orthrusdast.http.ScanHttpClient;
import ch.hug.orthrusdast.model.CWEReference;
import ch.hug.orthrusdast.model.Operation;
import ch.hug.orthrusdast.model.RiskLevel;
import ch.hug.orthrusdast.model.Vulnerability;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;

import java.util.Map;

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
        // Send an OPTIONS request with a fake Origin
        return httpClient.sendRaw(operation.url(), "OPTIONS", Map.of(
                "Origin", MALICIOUS_ORIGIN,
                "Access-Control-Request-Method", operation.method()
        ), null).flatMapMany(response -> {
            String acao = response.getHeader("Access-Control-Allow-Origin");
            String acac = response.getHeader("Access-Control-Allow-Credentials");

            boolean isVulnerable = false;
            String evidence = "";

            if (MALICIOUS_ORIGIN.equals(acao)) {
                isVulnerable = true;
                evidence = "Server reflected the malicious Origin ('" + MALICIOUS_ORIGIN + "') in Access-Control-Allow-Origin.";
                if ("true".equals(acac)) {
                    evidence += " It also allows credentials (Access-Control-Allow-Credentials: true), which is critical.";
                }
            } else if ("*".equals(acao) && "true".equals(acac)) {
                // Browsers usually block * with credentials, but it's a severe misconfig
                isVulnerable = true;
                evidence = "Server returned Access-Control-Allow-Origin: * along with Access-Control-Allow-Credentials: true.";
            }

            if (isVulnerable) {
                RiskLevel level = "true".equals(acac) ? RiskLevel.HIGH : RiskLevel.MEDIUM;
                Vulnerability vuln = Vulnerability.createWithDetails(
                        "CORS Misconfiguration",
                        "The endpoint has overly permissive Cross-Origin Resource Sharing (CORS) settings.",
                        level,
                        Vulnerability.Confidence.HIGH,
                        getId(),
                        operation,
                        CWEReference.CWE_942,
                        List.of("CAPEC-63"),
                                5.3,
                        evidence,
                        "Restrict Access-Control-Allow-Origin to trusted domains only. Do not reflect the Origin header blindly.",
                        "OPTIONS request sent with Origin: " + MALICIOUS_ORIGIN,
                        "Status: " + response.statusCode() + "\nAccess-Control-Allow-Origin: " + acao + "\nAccess-Control-Allow-Credentials: " + acac + "\nBody snippet: " + (response.body() != null && response.body().length() > 200 ? response.body().substring(0, 200) + "..." : String.valueOf(response.body()))
                ,
                                    "API Endpoint (Network)",
                                    "Unauthorized Access / Data Exposure");
                return Flux.just(vuln);
            }

            return Flux.empty();
        });
    }
}

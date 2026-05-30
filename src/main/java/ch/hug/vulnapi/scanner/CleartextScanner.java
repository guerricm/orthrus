package ch.hug.vulnapi.scanner;

import ch.hug.vulnapi.http.ScanHttpClient;
import ch.hug.vulnapi.model.CWEReference;
import ch.hug.vulnapi.model.Operation;
import ch.hug.vulnapi.model.RiskLevel;
import ch.hug.vulnapi.model.Vulnerability;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;

/**
 * Scans for Cleartext Transmission (CWE-319).
 */
@Component
public class CleartextScanner implements SecurityScanner {

    private final ScanHttpClient httpClient;

    public CleartextScanner(ScanHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public String getId() {
        return "cleartext-transmission";
    }

    @Override
    public String getName() {
        return "Cleartext Transmission Scanner";
    }

    @Override
    public Flux<Vulnerability> scan(Operation operation) {
        if (operation.url() != null && operation.url().toLowerCase().startsWith("http://")) {
            // Check if it's localhost or internal testing. We might still flag it but with lower severity.
            boolean isLocal = operation.url().contains("localhost") || operation.url().contains("127.0.0.1");
            
            Vulnerability vuln = Vulnerability.createWithDetails(
                    "Cleartext Transmission of Sensitive Information",
                    "The API endpoint is exposed over unencrypted HTTP. Data sent and received can be intercepted.",
                    isLocal ? RiskLevel.INFO : RiskLevel.MEDIUM,
                    Vulnerability.Confidence.HIGH,
                    getId(),
                    operation,
                    CWEReference.CWE_319,
                    "Cryptographic Failures",
                    "Endpoint uses 'http://' scheme.",
                    "Ensure all API endpoints are exclusively accessible via HTTPS. Implement HSTS (HTTP Strict Transport Security).",
                    "Observed URL scheme: " + operation.url(),
                    isLocal ? "Flagged as INFO because target appears to be local/development." : "Vulnerable endpoint."
            );
            return Flux.just(vuln);
        }
        return Flux.empty();
    }
}

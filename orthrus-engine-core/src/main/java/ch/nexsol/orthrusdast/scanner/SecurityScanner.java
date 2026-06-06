package ch.nexsol.orthrusdast.scanner;
import java.util.List;

import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.Vulnerability;
import ch.nexsol.orthrusdast.model.RiskLevel;
import ch.nexsol.orthrusdast.model.CWEReference;
import ch.nexsol.orthrusdast.http.ScanHttpResponse;
import reactor.core.publisher.Flux;

/**
 * Interface for all security scanners.
 */
public interface SecurityScanner {
    
    /**
     * @return the unique identifier of the scanner
     */
    String getId();

    /**
     * @return the human-readable name of the scanner
     */
    String getName();

    /**
     * Executes the scan on the given operation with context configuration.
     * @param operation the operation to scan
     * @param config the scan configuration
     * @return a Flux of found vulnerabilities
     */
    default Flux<Vulnerability> scan(Operation operation, ch.nexsol.orthrusdast.model.ScanConfiguration config) {
        return scan(operation);
    }

    /**
     * Executes the scan on the given operation.
     * @param operation the operation to scan
     * @return a Flux of found vulnerabilities
     */
    Flux<Vulnerability> scan(Operation operation);

    /**
     * Helper to create a Vulnerability with formatted HTTP traces.
     */
    default Vulnerability createVulnerabilityWithTrace(
            String name,
            String description,
            RiskLevel riskLevel,
            Vulnerability.Confidence confidence,
            Operation originalOp,
            CWEReference cwe,
            List<String> capecs,
            Double cvssScore,
            String evidence,
            String remediation,
            Operation testOp,
            ScanHttpResponse response,
            String attackVector,
            String technicalImpact
    ) {
        String reqDetails = formatRequest(testOp);
        String resDetails = response != null ? formatResponse(response) : "No Response";
        
        return Vulnerability.createWithDetails(
                name, description, riskLevel, confidence, getId(), originalOp, cwe, capecs, cvssScore,
                evidence, remediation, reqDetails, resDetails, attackVector, technicalImpact
        );
    }

    private String formatRequest(Operation op) {
        StringBuilder sb = new StringBuilder();
        String url = op.url();
        if (url != null && url.length() > 200) {
            url = url.substring(0, 200) + "...[TRUNCATED]";
        }
        sb.append(op.method()).append(" ").append(url);
        
        // Append query params if they aren't already in the URL
        if (op.queryParams() != null && !op.queryParams().isEmpty() && op.url() != null && !op.url().contains("?")) {
            sb.append("?");
            op.queryParams().forEach((k, v) -> {
                String val = v;
                if (val != null && val.length() > 100) val = val.substring(0, 100) + "...[TRUNCATED]";
                sb.append(k).append("=").append(val).append("&");
            });
            sb.setLength(sb.length() - 1); // remove last &
        }
        sb.append("\n");
        
        if (op.headers() != null) {
            op.headers().forEach((k, v) -> sb.append(k).append(": ").append(v).append("\n"));
        }
        sb.append("\n");
        if (op.body() != null && !op.body().isEmpty()) {
            sb.append(op.body().length() > 1000 ? op.body().substring(0, 1000) + "... [TRUNCATED]" : op.body());
        }
        return sb.toString();
    }

    private String formatResponse(ScanHttpResponse res) {
        StringBuilder sb = new StringBuilder();
        sb.append("Status: ").append(res.statusCode()).append("\n");
        if (res.headers() != null) {
            res.headers().forEach((k, values) -> {
                values.forEach(v -> sb.append(k).append(": ").append(v).append("\n"));
            });
        }
        sb.append("\n");
        if (res.body() != null) {
            sb.append(res.body().length() > 1000 ? res.body().substring(0, 1000) + "... [TRUNCATED]" : res.body());
        }
        return sb.toString();
    }
}

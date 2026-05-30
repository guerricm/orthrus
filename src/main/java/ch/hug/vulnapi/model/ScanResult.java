package ch.hug.vulnapi.model;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Result of a complete scan session.
 */
public record ScanResult(
        String id,
        String targetUrl,
        Instant scanStartTime,
        Instant scanEndTime,
        int operationsDiscovered,
        int operationsScanned,
        List<Vulnerability> vulnerabilities,
        Map<RiskLevel, Long> riskSummary,
        Map<String, Integer> scannerSummary,
        ScanConfiguration configuration,
        List<ScanAttempt> attempts
) {
}

package ch.nexsol.orthrusdast.model;

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
        List<ScanAttempt> attempts,
        String discovererId
) {
    public String formattedDuration() {
        if (scanStartTime == null || scanEndTime == null) return "0s";
        long seconds = java.time.Duration.between(scanStartTime, scanEndTime).getSeconds();
        if (seconds == 0) return "less than 1s";
        long mins = seconds / 60;
        long secs = seconds % 60;
        return mins > 0 ? mins + "m " + secs + "s" : secs + "s";
    }
}

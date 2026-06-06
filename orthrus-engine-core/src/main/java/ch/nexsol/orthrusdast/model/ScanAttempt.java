package ch.nexsol.orthrusdast.model;

import java.util.List;

/**
 * Represents a single execution of a specific scanner against a specific operation.
 */
public record ScanAttempt(
        String scannerId,
        String scannerName,
        String operationMethod,
        String operationUrl,
        AttemptStatus status,
        List<Vulnerability> vulnerabilities
) {
    public boolean passed() {
        return status == AttemptStatus.PASSED;
    }
}

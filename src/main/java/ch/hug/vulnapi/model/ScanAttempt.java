package ch.hug.vulnapi.model;

import java.util.List;

/**
 * Represents a single execution of a specific scanner against a specific operation.
 */
public record ScanAttempt(
        String scannerId,
        String scannerName,
        String operationMethod,
        String operationUrl,
        boolean passed,
        List<Vulnerability> vulnerabilities
) {
}

package ch.hug.orthrusdast.model;

import java.util.List;

/**
 * Configuration for a scan session.
 */
public record ScanConfiguration(
        List<String> includeScanners,
        List<String> excludeScanners,
        int concurrency,
        int httpConnectTimeoutMs,
        int httpReadTimeoutMs,
        boolean ignoreSslErrors,
        String reportFormat,
        SecurityScheme authScheme,
        SecurityScheme secondaryAuthScheme,
        String language,
        boolean includePassed,
        GatewayType gatewayType,
        String appUrl,
        String k8sToken
) {

    public static ScanConfiguration defaults() {
        return new ScanConfiguration(
                List.of(),
                List.of(),
                10,
                5000,
                10000,
                false,
                "json",
                null,
                null,
                "en",
                false,
                GatewayType.AUTO,
                null,
                null
        );
    }

    /**
     * Check if a scanner ID should be executed given include/exclude rules.
     */
    public boolean shouldRunScanner(String scannerId) {
        if (!includeScanners.isEmpty()) {
            return includeScanners.contains(scannerId);
        }
        return !excludeScanners.contains(scannerId);
    }
}

package ch.hug.orthrusdast.model;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Represents a single API operation (endpoint + method) to be scanned.
 * Aligned with vulnapi's Operation concept.
 */
public record Operation(
        String url,
        String method,
        Map<String, String> headers,
        Map<String, String> queryParams,
        String body,
        List<String> securityRequirements,
        List<String> expectedContentTypes,
        SecurityScheme authScheme
) {

    /**
     * Create a simple operation with just URL and method (for blackbox discovery).
     */
    public static Operation simple(String url, String method) {
        return new Operation(url, method, Collections.emptyMap(), Collections.emptyMap(),
                null, Collections.emptyList(), Collections.emptyList(), null);
    }

    /**
     * Create an operation with headers (for curl-like discovery).
     */
    public static Operation withHeaders(String url, String method, Map<String, String> headers, String body) {
        return new Operation(url, method, headers != null ? headers : Collections.emptyMap(),
                Collections.emptyMap(), body, Collections.emptyList(), Collections.emptyList(), null);
    }

    /**
     * Return a copy of this operation with the given auth scheme applied.
     */
    public Operation withAuth(SecurityScheme scheme) {
        return new Operation(url, method, headers, queryParams, body, securityRequirements, expectedContentTypes, scheme);
    }
}

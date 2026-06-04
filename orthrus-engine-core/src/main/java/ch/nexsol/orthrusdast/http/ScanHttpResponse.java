package ch.nexsol.orthrusdast.http;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import java.util.Map;

/**
 * Immutable representation of an HTTP response captured during scanning.
 */
public record ScanHttpResponse(
        HttpStatusCode statusCode,
        HttpHeaders headers,
        String body,
        long responseTimeMs
) {

    /**
     * Check if the response has a specific header.
     */
    public boolean hasHeader(String headerName) {
        return headers.getFirst(headerName) != null;
    }

    /**
     * Get a header value (first value only), or null.
     */
    public String getHeader(String headerName) {
        return headers.getFirst(headerName);
    }

    /**
     * Check if the status code is in the 2xx range.
     */
    public boolean isSuccessful() {
        return statusCode.is2xxSuccessful();
    }

    /**
     * Check if the body contains a specific string (case-insensitive).
     */
    public boolean bodyContains(String text) {
        return body != null && body.toLowerCase().contains(text.toLowerCase());
    }

    /**
     * Check if the body contains a specific string (case-sensitive).
     */
    public boolean bodyContainsExact(String text) {
        return body != null && body.contains(text);
    }
}

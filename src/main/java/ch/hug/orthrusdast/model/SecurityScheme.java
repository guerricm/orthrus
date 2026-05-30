package ch.hug.orthrusdast.model;

/**
 * Represents an authentication scheme to apply to scan requests.
 * Supports Bearer tokens, API keys, Basic auth, and OAuth2.
 */
public record SecurityScheme(
        AuthType type,
        String value,
        String headerName,
        String paramName,
        ParamLocation paramLocation
) {

    public enum AuthType {
        BEARER,
        API_KEY,
        BASIC,
        OAUTH2_CLIENT_CREDENTIALS,
        OAUTH2_AUTHORIZATION_CODE
    }

    public enum ParamLocation {
        HEADER,
        QUERY,
        COOKIE
    }

    /**
     * Create a Bearer token scheme.
     */
    public static SecurityScheme bearer(String token) {
        return new SecurityScheme(AuthType.BEARER, token, "Authorization", null, ParamLocation.HEADER);
    }

    /**
     * Create an API Key scheme (default: header-based).
     */
    public static SecurityScheme apiKey(String key, String headerName) {
        return new SecurityScheme(AuthType.API_KEY, key, headerName, null, ParamLocation.HEADER);
    }

    /**
     * Create an API Key scheme placed in a query parameter.
     */
    public static SecurityScheme apiKeyQuery(String key, String paramName) {
        return new SecurityScheme(AuthType.API_KEY, key, null, paramName, ParamLocation.QUERY);
    }

    /**
     * Create a Basic Auth scheme from username:password.
     */
    public static SecurityScheme basic(String username, String password) {
        String encoded = java.util.Base64.getEncoder().encodeToString((username + ":" + password).getBytes());
        return new SecurityScheme(AuthType.BASIC, encoded, "Authorization", null, ParamLocation.HEADER);
    }

    /**
     * Build the Authorization header value for this scheme.
     */
    public String toAuthorizationHeaderValue() {
        return switch (type) {
            case BEARER -> "Bearer " + value;
            case BASIC -> "Basic " + value;
            case API_KEY -> value;
            case OAUTH2_CLIENT_CREDENTIALS, OAUTH2_AUTHORIZATION_CODE -> "Bearer " + value;
        };
    }
}

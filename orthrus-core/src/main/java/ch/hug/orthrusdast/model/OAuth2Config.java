package ch.hug.orthrusdast.model;

import java.util.List;

/**
 * Configuration for OAuth2 token fetching.
 */
public record OAuth2Config(
        String tokenUrl,
        String clientId,
        String clientSecret,
        String grantType,
        List<String> credentials // e.g. "user:pass"
) {
}

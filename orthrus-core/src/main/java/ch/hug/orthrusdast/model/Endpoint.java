package ch.hug.orthrusdast.model;

import java.util.List;
import java.util.Map;

public record Endpoint(
        String url,
        String method,
        Map<String, String> headers,
        Map<String, String> queryParams,
        List<String> mockPayloads,
        List<String> securityRequirements,
        List<String> expectedContentTypes
) {
    public static Endpoint createSimple(String url, String method) {
        return new Endpoint(url, method, null, null, null, null, null);
    }
}

package ch.hug.vulnapi.auth;

import ch.hug.vulnapi.model.OAuth2Config;
import ch.hug.vulnapi.model.SecurityScheme;
import com.fasterxml.jackson.databind.JsonNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.List;

@Service
public class OAuth2TokenFetcher {

    private static final Logger log = LoggerFactory.getLogger(OAuth2TokenFetcher.class);
    private final WebClient webClient;

    public OAuth2TokenFetcher() {
        this.webClient = WebClient.create();
    }

    /**
     * Fetches tokens for all provided credentials or single client_credentials flow.
     */
    public Mono<List<SecurityScheme>> fetchTokens(OAuth2Config config) {
        if (config == null || config.tokenUrl() == null || config.grantType() == null) {
            return Mono.just(List.of());
        }

        if ("client_credentials".equalsIgnoreCase(config.grantType())) {
            return fetchSingleToken(config, null, null)
                    .map(List::of)
                    .defaultIfEmpty(List.of());
        } else if ("password".equalsIgnoreCase(config.grantType())) {
            if (config.credentials() == null || config.credentials().isEmpty()) {
                log.warn("Password grant type specified but no credentials provided");
                return Mono.just(List.of());
            }

            return Flux.fromIterable(config.credentials())
                    .concatMap(cred -> {
                        String[] parts = cred.split(":", 2);
                        if (parts.length != 2) {
                            log.warn("Invalid credential format, expected user:pass, got: {}", cred);
                            return Mono.empty();
                        }
                        return fetchSingleToken(config, parts[0], parts[1]);
                    })
                    .collectList();
        }

        log.warn("Unsupported grant type: {}", config.grantType());
        return Mono.just(List.of());
    }

    private Mono<SecurityScheme> fetchSingleToken(OAuth2Config config, String username, String password) {
        log.info("Fetching OAuth2 token from {} for user: {}", config.tokenUrl(), username != null ? username : "<client_credentials>");

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("grant_type", config.grantType());
        if (config.clientId() != null) {
            formData.add("client_id", config.clientId());
        }
        if (config.clientSecret() != null) {
            formData.add("client_secret", config.clientSecret());
        }
        if (username != null && password != null) {
            formData.add("username", username);
            formData.add("password", password);
        }

        return webClient.post()
                .uri(config.tokenUrl())
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
                .body(BodyInserters.fromFormData(formData))
                .retrieve()
                .bodyToMono(JsonNode.class)
                .map(json -> {
                    String token = json.path("access_token").asText();
                    if (token == null || token.isEmpty() || "null".equals(token)) {
                        throw new RuntimeException("No access_token found in response");
                    }
                    return SecurityScheme.bearer(token);
                })
                .doOnError(e -> log.error("Failed to fetch OAuth2 token: {}", e.getMessage()));
    }
}

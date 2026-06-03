package ch.hug.orthrusdast.http;

import ch.hug.orthrusdast.model.Operation;
import ch.hug.orthrusdast.model.SecurityScheme;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.Map;

/**
 * Reactive HTTP client wrapper around WebClient.
 * Centralizes all HTTP interactions for scanners:
 * - Timeout management
 * - Auth header injection
 * - Response capture (status, headers, body, timing)
 * - Error handling (returns response info even on 4xx/5xx)
 */
@Component
public class ScanHttpClient {

    private static final Logger log = LoggerFactory.getLogger(ScanHttpClient.class);

    private final WebClient webClient;

    public ScanHttpClient(WebClient webClient) {
        this.webClient = webClient;
    }

    /**
     * Send a request based on an Operation and return the captured response.
     */
    public Mono<ScanHttpResponse> send(Operation operation) {
        return send(operation, Map.of(), null);
    }

    /**
     * Send a request with extra headers (used by scanners to inject payloads).
     */
    public Mono<ScanHttpResponse> send(Operation operation, Map<String, String> extraHeaders, String bodyOverride) {
        long startTime = System.currentTimeMillis();

        HttpMethod method = HttpMethod.valueOf(operation.method().toUpperCase());

        WebClient.RequestBodySpec requestSpec = webClient.method(method)
                .uri(buildUri(operation))
                .headers(headers -> {
                    // Apply operation headers
                    if (operation.headers() != null) {
                        operation.headers().forEach(headers::set);
                    }
                    // Apply auth scheme
                    if (operation.authScheme() != null) {
                        applyAuth(headers, operation.authScheme());
                    }
                    // Apply extra headers (scanner-injected)
                    extraHeaders.forEach(headers::set);
                });

        String body = bodyOverride != null ? bodyOverride : operation.body();

        java.util.function.Function<ClientResponse, Mono<ScanHttpResponse>> responseHandler = clientResponse ->
                clientResponse.bodyToMono(String.class)
                        .defaultIfEmpty("")
                        .map(responseBody -> new ScanHttpResponse(
                                clientResponse.statusCode(),
                                clientResponse.headers().asHttpHeaders(),
                                responseBody,
                                System.currentTimeMillis() - startTime
                        ));

        Mono<ScanHttpResponse> resultMono;
        if (body != null && !body.isEmpty()) {
            String cType = operation.headers() != null ? operation.headers().get("Content-Type") : null;
            if (cType == null) cType = extraHeaders.get("Content-Type");
            if (cType != null) {
                requestSpec.contentType(org.springframework.http.MediaType.parseMediaType(cType));
            }
            resultMono = requestSpec.bodyValue(body).exchangeToMono(responseHandler);
        } else {
            resultMono = requestSpec.exchangeToMono(responseHandler);
        }

        return resultMono
                .timeout(Duration.ofSeconds(15))
                .onErrorResume(e -> {
                    log.warn("HTTP request failed for {} {}: {}", operation.method(), operation.url(), e.getMessage());
                    return Mono.just(new ScanHttpResponse(
                            org.springframework.http.HttpStatus.SERVICE_UNAVAILABLE,
                            new HttpHeaders(),
                            "Error: " + e.getMessage(),
                            System.currentTimeMillis() - startTime
                    ));
                });
    }

    /**
     * Send a raw request (no Operation) — used for well-known path discovery.
     */
    public Mono<ScanHttpResponse> sendGet(String url) {
        return send(Operation.simple(url, "GET"));
    }

    /**
     * Send a raw request with custom method.
     */
    public Mono<ScanHttpResponse> sendRaw(String url, String method, Map<String, String> headers, String body) {
        Operation op = Operation.withHeaders(url, method, headers, body);
        return send(op);
    }

    /**
     * Send the same request multiple times rapidly (for rate-limiting tests).
     */
    public Mono<ScanHttpResponse> sendNTimes(Operation operation, int count) {
        return Mono.defer(() -> send(operation))
                .repeat(count - 1)
                .last();
    }

    private java.net.URI buildUri(Operation operation) {
        org.springframework.web.util.UriComponentsBuilder builder = org.springframework.web.util.UriComponentsBuilder.fromUriString(operation.url());
        if (operation.queryParams() != null) {
            operation.queryParams().forEach(builder::queryParam);
        }
        return builder.build().encode().toUri();
    }

    private void applyAuth(HttpHeaders headers, SecurityScheme scheme) {
        if (scheme.paramLocation() == SecurityScheme.ParamLocation.HEADER) {
            String headerName = scheme.headerName() != null ? scheme.headerName() : "Authorization";
            headers.set(headerName, scheme.toAuthorizationHeaderValue());
        }
        // Query param auth is handled in buildUri
    }
}

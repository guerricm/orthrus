package ch.nexsol.orthrusdast.api;

// ch.nexsol.orthrusdast.engine.ScanService removed
import ch.nexsol.orthrusdast.model.OAuth2Config;
import ch.nexsol.orthrusdast.auth.OAuth2TokenFetcher;
import ch.nexsol.orthrusdast.model.ScanConfiguration;
import ch.nexsol.orthrusdast.model.GatewayType;
import ch.nexsol.orthrusdast.model.ScanResult;
import ch.nexsol.orthrusdast.model.SecurityScheme;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * Reactive REST Controller for triggering scans via HTTP.
 */
@RestController
@RequestMapping("/api/v1/scans")
public class ScanController {

    private final OAuth2TokenFetcher tokenFetcher;
    private final ch.nexsol.orthrusdast.repository.ScanJobRepository scanJobRepository;
    private final tools.jackson.databind.ObjectMapper objectMapper;

    public ScanController(OAuth2TokenFetcher tokenFetcher, ch.nexsol.orthrusdast.repository.ScanJobRepository scanJobRepository, tools.jackson.databind.ObjectMapper objectMapper) {
        this.tokenFetcher = tokenFetcher;
        this.scanJobRepository = scanJobRepository;
        this.objectMapper = objectMapper;
    }

    /**
     * Get available discoverers.
     */
    @GetMapping("/discoverers")
    public Mono<List<String>> getDiscoverers() {
        return Mono.just(List.of("openapi", "graphql", "blackbox", "well-known", "curl"));
    }

    /**
     * Trigger a new scan.
     * Note: In a real production app, this would likely enqueue the scan and return an ID,
     * but for this v1 we'll block the connection and return the result directly (since we don't have a DB).
     */
    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public Mono<ResponseEntity<ScanResult>> triggerScan(@RequestBody ScanRequest request) {

        return Mono.justOrEmpty(request.oauth2())
                .flatMap(oauth2Config -> tokenFetcher.fetchTokens(oauth2Config))
                .defaultIfEmpty(List.of())
                .flatMap(fetchedTokens -> {
                    SecurityScheme authScheme = request.authScheme();
                    SecurityScheme secondaryAuthScheme = request.secondaryAuthScheme();

                    if (!fetchedTokens.isEmpty()) {
                        authScheme = fetchedTokens.get(0);
                        if (fetchedTokens.size() > 1) {
                            secondaryAuthScheme = fetchedTokens.get(1);
                        }
                    }

                    ScanConfiguration config = new ScanConfiguration(
                            request.includeScanners() != null ? request.includeScanners() : List.of(),
                            request.excludeScanners() != null ? request.excludeScanners() : List.of(),
                            request.concurrency() > 0 ? request.concurrency() : 10,
                            5000,
                            10000,
                            request.ignoreSslErrors(),
                            "json",
                            authScheme,
                            secondaryAuthScheme,
                            request.language() != null ? request.language() : "en",
                            request.includePassed() != null ? request.includePassed() : false,
                            GatewayType.AUTO,
                            null,
                            null
                    );

                    try {
                        String configJson = objectMapper.writeValueAsString(config);
                        ch.nexsol.orthrusdast.entity.ScanJobEntity job = new ch.nexsol.orthrusdast.entity.ScanJobEntity(
                                request.discovererId(), request.target(), configJson, ch.nexsol.orthrusdast.model.JobStatus.PENDING
                        );
                        return scanJobRepository.save(job)
                                .map(savedJob -> ResponseEntity.accepted().body((ScanResult) null)); // Need a DTO or just return job ID
                    } catch (Exception e) {
                        return Mono.error(e);
                    }
                })
                .onErrorResume(IllegalArgumentException.class, e ->
                        Mono.just(ResponseEntity.badRequest().build()))
                .onErrorResume(Exception.class, e ->
                        Mono.just(ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build()));
    }

    // DTO for incoming requests
    public record ScanRequest(
            String discovererId, // e.g. 'openapi', 'blackbox', 'curl'
            String target,
            String overrideHost,
            List<String> includeScanners,
            List<String> excludeScanners,
            int concurrency,
            boolean ignoreSslErrors,
            SecurityScheme authScheme,
            SecurityScheme secondaryAuthScheme,
            OAuth2Config oauth2,
            String language,
            Boolean includePassed
    ) {}
}

package ch.hug.vulnapi.api;

import ch.hug.vulnapi.engine.ScanService;
import ch.hug.vulnapi.model.ScanConfiguration;
import ch.hug.vulnapi.model.ScanResult;
import ch.hug.vulnapi.model.SecurityScheme;
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

    private final ScanService scanService;

    public ScanController(ScanService scanService) {
        this.scanService = scanService;
    }

    /**
     * Get available discoverers.
     */
    @GetMapping("/discoverers")
    public Mono<List<String>> getDiscoverers() {
        return Mono.just(scanService.getAvailableDiscoverers());
    }

    /**
     * Trigger a new scan.
     * Note: In a real production app, this would likely enqueue the scan and return an ID,
     * but for this v1 we'll block the connection and return the result directly (since we don't have a DB).
     */
    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public Mono<ResponseEntity<ScanResult>> triggerScan(@RequestBody ScanRequest request) {
        
        ScanConfiguration config = new ScanConfiguration(
                request.includeScanners() != null ? request.includeScanners() : List.of(),
                request.excludeScanners() != null ? request.excludeScanners() : List.of(),
                request.concurrency() > 0 ? request.concurrency() : 10,
                5000,
                10000,
                request.ignoreSslErrors(),
                "json",
                request.authScheme(),
                request.secondaryAuthScheme(),
                request.language() != null ? request.language() : "en"
        );

        return scanService.executeScan(request.discovererId(), request.target(), request.overrideHost(), config)
                .map(result -> ResponseEntity.ok(result))
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
            String language
    ) {}
}

package ch.hug.vulnapi.engine;

import ch.hug.vulnapi.ingestion.EndpointDiscoverer;
import ch.hug.vulnapi.model.Operation;
import ch.hug.vulnapi.model.RiskLevel;
import ch.hug.vulnapi.model.ScanConfiguration;
import ch.hug.vulnapi.model.ScanResult;
import ch.hug.vulnapi.model.Vulnerability;
import ch.hug.vulnapi.scanner.SecurityScanner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Core engine that orchestrates the scanning process reactively.
 */
@Service
public class ScanEngine {

    private static final Logger log = LoggerFactory.getLogger(ScanEngine.class);
    private final List<SecurityScanner> allScanners;

    public ScanEngine(List<SecurityScanner> scanners) {
        this.allScanners = scanners;
    }

    /**
     * Runs a complete scan asynchronously.
     */
    public Mono<ScanResult> runScan(EndpointDiscoverer discoverer, String targetUrl, String overrideHost, ScanConfiguration config) {
        log.info("Starting scan engine with concurrency: {}", config.concurrency());
        Instant startTime = Instant.now();

        // Filter scanners based on configuration
        List<SecurityScanner> activeScanners = allScanners.stream()
                .filter(s -> config.shouldRunScanner(s.getId()))
                .toList();

        log.info("Active scanners: {}", activeScanners.stream().map(SecurityScanner::getId).toList());

        // Thread-safe accumulators for stats
        Map<RiskLevel, Long> riskSummary = new ConcurrentHashMap<>();
        for (RiskLevel level : RiskLevel.values()) {
            riskSummary.put(level, 0L);
        }
        Map<String, Integer> scannerSummary = new ConcurrentHashMap<>();
        
        return discoverer.discover(targetUrl, overrideHost, config.authScheme())
                .flatMap(operations -> {
                    log.info("Discovered {} operations to scan.", operations.size());

                    if (operations.isEmpty()) {
                        return Mono.just(createEmptyResult(targetUrl, startTime, config));
                    }

                    // Process operations in parallel
                    Flux<Vulnerability> vulnerabilitiesFlux = Flux.fromIterable(operations)
                            .flatMap(operation -> scanOperation(operation, activeScanners, config), config.concurrency());

                    return vulnerabilitiesFlux
                            .doOnNext(vuln -> {
                                log.warn("Found vulnerability: {} [{}] on {}", vuln.name(), vuln.riskLevel(), vuln.operationUrl());
                                riskSummary.compute(vuln.riskLevel(), (k, v) -> v + 1);
                                scannerSummary.compute(vuln.scannerId(), (k, v) -> (v == null ? 0 : v) + 1);
                            })
                            .collectList()
                            .map(vulns -> {
                                Instant endTime = Instant.now();
                                log.info("Scan completed. Found {} vulnerabilities.", vulns.size());
                                return new ScanResult(
                                        UUID.randomUUID().toString(),
                                        targetUrl,
                                        startTime,
                                        endTime,
                                        operations.size(),
                                        operations.size(),
                                        vulns,
                                        new EnumMap<>(riskSummary),
                                        new HashMap<>(scannerSummary),
                                        config
                                );
                            });
                });
    }

    private Flux<Vulnerability> scanOperation(Operation operation, List<SecurityScanner> scanners, ScanConfiguration config) {
        log.debug("Scanning operation: {} {}", operation.method(), operation.url());
        return Flux.fromIterable(scanners)
                .flatMap(scanner -> scanner.scan(operation, config)
                        .onErrorResume(e -> {
                            log.error("Scanner {} failed on operation {}: {}", scanner.getId(), operation.url(), e.getMessage());
                            return Flux.empty();
                        })
                );
    }
    
    private ScanResult createEmptyResult(String targetUrl, Instant startTime, ScanConfiguration config) {
        Map<RiskLevel, Long> riskSummary = new EnumMap<>(RiskLevel.class);
        for (RiskLevel level : RiskLevel.values()) {
            riskSummary.put(level, 0L);
        }
        return new ScanResult(
                UUID.randomUUID().toString(),
                targetUrl,
                startTime,
                Instant.now(),
                0,
                0,
                List.of(),
                riskSummary,
                Map.of(),
                config
        );
    }
}

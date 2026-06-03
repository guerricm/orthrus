package ch.hug.orthrusdast.engine;

import ch.hug.orthrusdast.ingestion.EndpointDiscoverer;
import ch.hug.orthrusdast.model.Operation;
import ch.hug.orthrusdast.model.RiskLevel;
import ch.hug.orthrusdast.model.ScanConfiguration;
import ch.hug.orthrusdast.model.ScanResult;
import ch.hug.orthrusdast.model.ScanAttempt;
import ch.hug.orthrusdast.model.Vulnerability;
import ch.hug.orthrusdast.scanner.SecurityScanner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

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

    public List<SecurityScanner> getAllScanners() {
        return allScanners;
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
        return discoverer.discover(targetUrl, overrideHost, config)
                .flatMap(operations -> {
                    if (operations.isEmpty()) {
                        log.error("No operations discovered. Scan cannot proceed.");
                        return Mono.error(new IllegalStateException("Discovery failed or no endpoints found. Please check your target URL and documentation."));
                    }

                    log.info("Discovered {} operations. Starting scan...", operations.size());

                    Map<RiskLevel, Long> riskSummaryAccumulator = new EnumMap<>(RiskLevel.class);
                    for (RiskLevel level : RiskLevel.values()) {
                        riskSummaryAccumulator.put(level, 0L);
                    }
                    Map<String, Integer> scannerSummary = new HashMap<>();

                    Flux<ScanAttempt> attemptsFlux = Flux.fromIterable(operations)
                            .flatMap(op -> scanOperation(op, activeScanners, config), config.concurrency());

                    return attemptsFlux
                            .doOnNext(attempt -> {
                                for (Vulnerability vuln : attempt.vulnerabilities()) {
                                    log.warn("Found vulnerability: {} [{}] on {}", vuln.name(), vuln.riskLevel(), vuln.operationUrl());
                                    riskSummaryAccumulator.compute(vuln.riskLevel(), (k, v) -> v + 1);
                                    scannerSummary.compute(vuln.scannerId(), (k, v) -> (v == null ? 0 : v) + 1);
                                }
                            })
                            .collectList()
                            .map(attempts -> {
                                Instant endTime = Instant.now();
                                
                                List<Vulnerability> allVulns = attempts.stream()
                                    .flatMap(a -> a.vulnerabilities().stream())
                                    .collect(Collectors.toList());
                                
                                List<Vulnerability> sortedVulns = new java.util.ArrayList<>(allVulns);
                                sortedVulns.sort(java.util.Comparator.comparing(Vulnerability::riskLevel).reversed());

                                ScanResult result = new ScanResult(
                                        UUID.randomUUID().toString(),
                                        targetUrl,
                                        startTime,
                                        endTime,
                                        operations.size(),
                                        operations.size(),
                                        sortedVulns,
                                        new EnumMap<>(riskSummaryAccumulator),
                                        new HashMap<>(scannerSummary),
                                        config,
                                        config.includePassed() ? sortAttempts(attempts) : List.of()
                                );
                                
                                log.info("Scan completed in {}. Found {} vulnerabilities in {} executed tests.", result.formattedDuration(), allVulns.size(), attempts.size());

                                return result;
                            });
                });
    }

    private Flux<ScanAttempt> scanOperation(Operation operation, List<SecurityScanner> scanners, ScanConfiguration config) {
        log.debug("Scanning operation: {} {}", operation.method(), operation.url());
        return Flux.fromIterable(scanners)
                .flatMap(scanner -> scanner.scan(operation, config)
                        .collectList()
                        .map(vulns -> new ScanAttempt(
                                scanner.getId(), 
                                scanner.getName(), 
                                operation.method(), 
                                operation.url(), 
                                vulns.isEmpty(), 
                                vulns
                        ))
                        .onErrorResume(e -> {
                            log.error("Scanner {} failed on operation {}: {}", scanner.getId(), operation.url(), e.getMessage());
                            return Mono.just(new ScanAttempt(
                                    scanner.getId(), 
                                    scanner.getName(), 
                                    operation.method(), 
                                    operation.url(), 
                                    false, 
                                    List.of()
                            ));
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
                new EnumMap<>(riskSummary),
                new HashMap<>(),
                config,
                List.of()
        );
    }

    /**
     * Sort attempts by endpoint URL, method, scanner name, then status (failed first).
     */
    private List<ScanAttempt> sortAttempts(List<ScanAttempt> attempts) {
        List<ScanAttempt> sorted = new ArrayList<>(attempts);
        sorted.sort(Comparator.comparing(ScanAttempt::operationUrl)
                .thenComparing(ScanAttempt::operationMethod)
                .thenComparing(ScanAttempt::scannerName)
                .thenComparing(ScanAttempt::passed)); // false (failed) < true (passed)
        return sorted;
    }
}

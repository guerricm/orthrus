package ch.nexsol.orthrusdast.engine;

import ch.nexsol.orthrusdast.ingestion.EndpointDiscoverer;
import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.RiskLevel;
import ch.nexsol.orthrusdast.model.ScanConfiguration;

import ch.nexsol.orthrusdast.model.ScanAttempt;
import ch.nexsol.orthrusdast.model.Vulnerability;
import ch.nexsol.orthrusdast.scanner.SecurityScanner;
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
    private final ch.nexsol.orthrusdast.http.ScanHttpClient httpClient;

    public ScanEngine(List<SecurityScanner> scanners, ch.nexsol.orthrusdast.http.ScanHttpClient httpClient) {
        this.allScanners = scanners;
        this.httpClient = httpClient;
    }

    public List<SecurityScanner> getAllScanners() {
        return allScanners;
    }

    /**
     * Runs a complete scan asynchronously.
     */
    public Flux<ScanAttempt> runScan(EndpointDiscoverer discoverer, String targetUrl, ScanConfiguration config) {
        log.info("Starting scan engine with concurrency: {}", config.concurrency());
        Instant startTime = Instant.now();

        // Filter scanners based on configuration
        List<SecurityScanner> activeScanners = allScanners.stream()
                .filter(s -> config.shouldRunScanner(s.getId()))
                .toList();

        log.info("Active scanners: {}", activeScanners.stream().map(SecurityScanner::getId).toList());

        return discoverer.discover(targetUrl, config)
                .flatMapMany(operations -> {
                    if (operations.isEmpty()) {
                        log.error("No operations discovered. Scan cannot proceed.");
                        return Flux.error(new IllegalStateException("Discovery failed or no endpoints found. Please check your target URL and documentation."));
                    }

                    log.info("Discovered {} operations. Starting scan...", operations.size());

                    return Flux.fromIterable(operations)
                            .flatMap(op -> scanOperation(op, activeScanners, config), config.concurrency())
                            .doOnNext(attempt -> {
                                for (Vulnerability vuln : attempt.vulnerabilities()) {
                                    log.warn("Found vulnerability: {} [{}] on {}", vuln.name(), vuln.riskLevel(), vuln.operationUrl());
                                }
                            });
                });
    }

    private Flux<ScanAttempt> scanOperation(Operation operation, List<SecurityScanner> scanners, ScanConfiguration config) {
        log.debug("Scanning operation: {} {}", operation.method(), operation.url());
        return httpClient.send(operation).flatMapMany(response -> {
            if (response.statusCode().value() == 401 || response.statusCode().value() == 403) {
                log.warn("Operation {} {} returned auth error {}. Skipping scanners.", operation.method(), operation.url(), response.statusCode().value());
                return Flux.fromIterable(scanners)
                        .map(scanner -> new ScanAttempt(
                                scanner.getId(), 
                                scanner.getName(), 
                                operation.method(), 
                                operation.url(), 
                                ch.nexsol.orthrusdast.model.AttemptStatus.AUTH_ERROR, 
                                List.of()
                        ));
            }

            return Flux.fromIterable(scanners)
                    .flatMap(scanner -> scanner.scan(operation, config)
                            .collectList()
                            .map(vulns -> new ScanAttempt(
                                    scanner.getId(), 
                                    scanner.getName(), 
                                    operation.method(), 
                                    operation.url(), 
                                    vulns.isEmpty() ? ch.nexsol.orthrusdast.model.AttemptStatus.PASSED : ch.nexsol.orthrusdast.model.AttemptStatus.FAILED, 
                                    vulns
                            ))
                            .onErrorResume(e -> {
                                log.error("Scanner {} failed on operation {}: {}", scanner.getId(), operation.url(), e.getMessage());
                                return Mono.just(new ScanAttempt(
                                        scanner.getId(), 
                                        scanner.getName(), 
                                        operation.method(), 
                                        operation.url(), 
                                        ch.nexsol.orthrusdast.model.AttemptStatus.ERROR, 
                                        List.of()
                                ));
                            })
                    );
        });
    }
    

}

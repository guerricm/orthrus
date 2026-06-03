package ch.hug.orthrusdast.engine;

import ch.hug.orthrusdast.ingestion.EndpointDiscoverer;
import ch.hug.orthrusdast.model.ScanConfiguration;
import ch.hug.orthrusdast.model.ScanResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * High-level orchestration service.
 * Finds the right discoverer and triggers the ScanEngine.
 */
@Service
public class ScanService {

    private static final Logger log = LoggerFactory.getLogger(ScanService.class);
    
    private final ScanEngine scanEngine;
    private final Map<String, EndpointDiscoverer> discoverers;

    public ScanService(ScanEngine scanEngine, List<EndpointDiscoverer> discovererList) {
        this.scanEngine = scanEngine;
        this.discoverers = discovererList.stream()
                .collect(Collectors.toMap(EndpointDiscoverer::getId, Function.identity()));
    }

    /**
     * Execute a scan based on a target and a specific discoverer ID.
     */
    public Mono<ScanResult> executeScan(String discovererId, String target, String overrideHost, ScanConfiguration config) {
        EndpointDiscoverer discoverer = discoverers.get(discovererId);
        if (discoverer == null) {
            return Mono.error(new IllegalArgumentException("Unknown discoverer ID: " + discovererId));
        }

        log.info("Executing scan with discoverer '{}' on target '{}'", discovererId, target);
        
        return scanEngine.runScan(discoverer, target, overrideHost, config);
    }
    
    /**
     * Get a list of available discoverers.
     */
    public List<String> getAvailableDiscoverers() {
        return discoverers.keySet().stream().sorted().toList();
    }

    /**
     * Get a list of available scanner IDs.
     */
    public List<String> getAvailableScanners() {
        return scanEngine.getAllScanners().stream()
                .map(ch.hug.orthrusdast.scanner.SecurityScanner::getId)
                .sorted()
                .toList();
    }

    /**
     * Get a list of available scanner objects (useful for UI display with names/descriptions).
     */
    public List<ch.hug.orthrusdast.scanner.SecurityScanner> getAvailableScannerObjects() {
        return scanEngine.getAllScanners().stream()
                .sorted(java.util.Comparator.comparing(ch.hug.orthrusdast.scanner.SecurityScanner::getId))
                .toList();
    }
}

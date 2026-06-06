package ch.nexsol.orthrusdast.api;

import ch.nexsol.orthrusdast.client.MasterApiClient;
import ch.nexsol.orthrusdast.engine.ScanService;
import ch.nexsol.orthrusdast.model.ScanConfiguration;
import tools.jackson.databind.ObjectMapper;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import ch.nexsol.orthrusdast.model.NodeStatus;
import java.util.List;

@RestController
@RequestMapping("/api/v1/slave")
@ConditionalOnProperty(name = "orthrus.slave.mode", havingValue = "server", matchIfMissing = true)
public class SlaveApiController {

    private final ScanService scanService;
    private final MasterApiClient masterApiClient;
    private final ObjectMapper objectMapper;
    private final java.util.Map<Long, reactor.core.Disposable> activeJobs = new java.util.concurrent.ConcurrentHashMap<>();

    public SlaveApiController(ScanService scanService, MasterApiClient masterApiClient, ObjectMapper objectMapper) {
        this.scanService = scanService;
        this.masterApiClient = masterApiClient;
        this.objectMapper = objectMapper;
    }

    @PostMapping("/scans")
    public Mono<ResponseEntity<Void>> receiveScanJob(@RequestBody ScanJobRequest request) {
        // Mark as BUSY
        masterApiClient.setStatus(NodeStatus.BUSY);

        return Mono.fromCallable(() -> objectMapper.readValue(request.scanConfigurationJson(), ScanConfiguration.class))
                .flatMap(config -> {
                    java.time.Instant startTime = java.time.Instant.now();
                    java.util.concurrent.atomic.AtomicInteger testsCount = new java.util.concurrent.atomic.AtomicInteger();
                    java.util.concurrent.atomic.AtomicInteger vulnsCount = new java.util.concurrent.atomic.AtomicInteger();
                    
                    reactor.core.Disposable disposable = scanService.executeScan(request.discovererId(), request.target(), null, config)
                            .bufferTimeout(10, java.time.Duration.ofSeconds(1))
                            .flatMap(batch -> {
                                testsCount.addAndGet(batch.size());
                                for (ch.nexsol.orthrusdast.model.ScanAttempt attempt : batch) {
                                    if (attempt.vulnerabilities() != null) {
                                        vulnsCount.addAndGet(attempt.vulnerabilities().size());
                                    }
                                }
                                return masterApiClient.sendJobAttemptsBatch(request.jobId(), batch);
                            })
                            .then(Mono.defer(() -> {
                                org.slf4j.LoggerFactory.getLogger(SlaveApiController.class)
                                        .info("Scan job {} completed. {} tests executed, {} vulnerabilities found.", request.jobId(), testsCount.get(), vulnsCount.get());
                                return masterApiClient.completeJob(request.jobId(), startTime);
                            }))
                            .doOnError(e -> {
                                masterApiClient.setStatus(NodeStatus.IDLE);
                                org.slf4j.LoggerFactory.getLogger(SlaveApiController.class)
                                        .error("Error executing scan job", e);
                            })
                            .doFinally(signalType -> activeJobs.remove(request.jobId()))
                            .subscribeOn(Schedulers.boundedElastic())
                            .subscribe();

                    activeJobs.put(request.jobId(), disposable);

                    return Mono.just(ResponseEntity.accepted().<Void>build());
                })
                .onErrorResume(e -> {
                    masterApiClient.setStatus(NodeStatus.IDLE);
                    return Mono.just(ResponseEntity.badRequest().<Void>build());
                });
    }

    @DeleteMapping("/scans/{id}")
    public Mono<ResponseEntity<Void>> cancelScanJob(@PathVariable Long id) {
        reactor.core.Disposable disposable = activeJobs.remove(id);
        if (disposable != null && !disposable.isDisposed()) {
            disposable.dispose();
            masterApiClient.setStatus(NodeStatus.IDLE);
            return Mono.just(ResponseEntity.ok().<Void>build());
        }
        return Mono.just(ResponseEntity.notFound().build());
    }

    @GetMapping("/capabilities")
    public Mono<ResponseEntity<CapabilitiesResponse>> getCapabilities() {
        List<ScannerInfo> scanners = scanService.getAvailableScannerObjects().stream()
                .map(s -> new ScannerInfo(s.getId(), s.getName()))
                .toList();
        return Mono.just(ResponseEntity.ok(new CapabilitiesResponse(
                scanService.getAvailableDiscoverers(),
                scanners
        )));
    }

    public record CapabilitiesResponse(List<String> discoverers, List<ScannerInfo> scanners) {}
    public record ScannerInfo(String id, String name) {}

    public record ScanJobRequest(Long jobId, String discovererId, String target, String scanConfigurationJson) {}
}

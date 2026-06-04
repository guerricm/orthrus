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

    public SlaveApiController(ScanService scanService, MasterApiClient masterApiClient, ObjectMapper objectMapper) {
        this.scanService = scanService;
        this.masterApiClient = masterApiClient;
        this.objectMapper = objectMapper;
    }

    @PostMapping("/scans")
    public Mono<ResponseEntity<Void>> receiveScanJob(@RequestBody ScanJobRequest request) {
        // Mark as BUSY
        masterApiClient.setStatus(NodeStatus.BUSY);

        try {
            ScanConfiguration config = objectMapper.readValue(request.scanConfigurationJson(), ScanConfiguration.class);
            
            // Execute the scan asynchronously (fire and forget from the HTTP response perspective)
            scanService.executeScan(request.discovererId(), request.target(), null, config)
                    .flatMap(result -> masterApiClient.sendJobResult(request.jobId(), result))
                    .subscribeOn(Schedulers.boundedElastic())
                    .subscribe();

            return Mono.just(ResponseEntity.accepted().build());
        } catch (Exception e) {
            masterApiClient.setStatus(NodeStatus.IDLE);
            return Mono.just(ResponseEntity.badRequest().build());
        }
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

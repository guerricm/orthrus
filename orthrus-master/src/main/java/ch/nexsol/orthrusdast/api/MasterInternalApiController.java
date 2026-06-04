package ch.nexsol.orthrusdast.api;

import ch.nexsol.orthrusdast.entity.SlaveNodeEntity;
import ch.nexsol.orthrusdast.entity.ScanJobEntity;
import ch.nexsol.orthrusdast.model.ScanResult;
import ch.nexsol.orthrusdast.repository.SlaveNodeRepository;
import ch.nexsol.orthrusdast.repository.ScanJobRepository;
import ch.nexsol.orthrusdast.engine.ScanResultService;
import ch.nexsol.orthrusdast.model.NodeStatus;
import ch.nexsol.orthrusdast.model.JobStatus;
import ch.nexsol.orthrusdast.model.RiskLevel;
import ch.nexsol.orthrusdast.sse.JobEvent;
import ch.nexsol.orthrusdast.sse.JobEventPublisher;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.codec.ServerSentEvent;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

@RestController
@RequestMapping("/api/internal")
public class MasterInternalApiController {

    private final SlaveNodeRepository slaveNodeRepository;
    private final ScanJobRepository scanJobRepository;
    private final ScanResultService scanResultService;
    private final JobEventPublisher jobEventPublisher;

    public MasterInternalApiController(SlaveNodeRepository slaveNodeRepository, ScanJobRepository scanJobRepository,
            ScanResultService scanResultService, JobEventPublisher jobEventPublisher) {
        this.slaveNodeRepository = slaveNodeRepository;
        this.scanJobRepository = scanJobRepository;
        this.scanResultService = scanResultService;
        this.jobEventPublisher = jobEventPublisher;
    }

    /**
     * Called by Slave to register its presence.
     */
    @PostMapping("/slaves/register")
    public Mono<ResponseEntity<SlaveNodeEntity>> registerSlave(@RequestBody SlaveRegistrationRequest request) {
        SlaveNodeEntity node = new SlaveNodeEntity(request.id(), request.url(), NodeStatus.IDLE);
        return slaveNodeRepository.findById(node.getId())
                .flatMap(existing -> slaveNodeRepository
                        .updateSlaveNodeUrlStatusAndLastSeenAt(node.getId(), node.getUrl(), node.getStatus().name(),
                                node.getLastSeenAt())
                        .thenReturn(ResponseEntity.ok(node)))
                .switchIfEmpty(Mono.defer(() -> slaveNodeRepository
                        .insertSlaveNode(node.getId(), node.getUrl(), node.getStatus(), node.getLastSeenAt())
                        .thenReturn(ResponseEntity.ok(node))));
    }

    /**
     * Called by Slave to send a heartbeat.
     */
    @PostMapping("/slaves/{id}/heartbeat")
    public Mono<ResponseEntity<Void>> slaveHeartbeat(@PathVariable String id,
            @RequestParam(defaultValue = "IDLE") NodeStatus status) {
        return slaveNodeRepository.updateSlaveNodeStatusAndLastSeenAt(id, status.name(), Instant.now())
                .flatMap(rows -> {
                    if (rows == 0) {
                        return Mono.just(ResponseEntity.notFound().build());
                    }
                    return Mono.just(ResponseEntity.ok().<Void>build());
                });
    }

    /**
     * Called by Slave to post the final result of a scan.
     */
    @PostMapping("/jobs/{id}/result")
    public Mono<ResponseEntity<Void>> postJobResult(@PathVariable Long id, @RequestBody ScanResult result) {
        return scanJobRepository.findById(id)
                .flatMap(job -> {
                    job.setStatus(JobStatus.COMPLETED);
                    job.setCompletedAt(Instant.now());
                    
                    return scanResultService.save(result)
                            .flatMap(savedResult -> {
                                job.setResultId(savedResult.id());
                                job.setVulnsCount(result.vulnerabilities() != null ? result.vulnerabilities().size() : 0);
                                job.setTestsCount(result.attempts() != null ? result.attempts().size() : 0);
                                return scanJobRepository.save(job)
                                        .doOnSuccess(j -> {
                                            long critical = result.riskSummary().getOrDefault(RiskLevel.CRITICAL, 0L);
                                            long high = result.riskSummary().getOrDefault(RiskLevel.HIGH, 0L);
                                            long medium = result.riskSummary().getOrDefault(RiskLevel.MEDIUM, 0L);
                                            long low = result.riskSummary().getOrDefault(RiskLevel.LOW, 0L);
                                            String grade = "A";
                                            if (critical > 0) grade = "F";
                                            else if (high > 0) grade = "D";
                                            else if (medium > 0) grade = "C";
                                            else if (low > 0) grade = "B";

                                            long info = result.riskSummary().getOrDefault(RiskLevel.INFO, 0L);

                                            jobEventPublisher.emit(id, JobEvent.completed(
                                                    id, job.getTarget(), savedResult.id(),
                                                    grade, result.vulnerabilities().size(),
                                                    critical, high, medium, low, info,
                                                    result.operationsScanned()));
                                            jobEventPublisher.complete(id);
                                            
                                            // Update slave status
                                            if (job.getAssignedSlaveId() != null) {
                                                slaveNodeRepository.findById(job.getAssignedSlaveId())
                                                    .flatMap(slave -> scanJobRepository.countByAssignedSlaveIdAndStatus(slave.getId(), JobStatus.RUNNING)
                                                        .flatMap(runningCount -> {
                                                            if (runningCount < slave.getMaxConcurrentScans()) {
                                                                return slaveNodeRepository.updateSlaveNodeStatusAndLastSeenAt(slave.getId(), NodeStatus.IDLE.name(), slave.getLastSeenAt());
                                                            }
                                                            return Mono.empty();
                                                        }))
                                                    .subscribe();
                                            }
                                        });
                            });
                })
                .map(j -> ResponseEntity.ok().<Void>build())
                .defaultIfEmpty(ResponseEntity.notFound().build());
    }

    public record SlaveRegistrationRequest(String id, String url) {
    }
}

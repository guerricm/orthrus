package ch.nexsol.orthrusdast.scheduler;

import ch.nexsol.orthrusdast.entity.ScanJobEntity;
import ch.nexsol.orthrusdast.entity.SlaveNodeEntity;
import ch.nexsol.orthrusdast.repository.ScanJobRepository;
import ch.nexsol.orthrusdast.repository.SlaveNodeRepository;
import org.springframework.http.MediaType;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import ch.nexsol.orthrusdast.model.NodeStatus;
import ch.nexsol.orthrusdast.model.JobStatus;
import reactor.core.publisher.Mono;

import java.time.Instant;

@Component
@EnableScheduling
public class JobDispatcherScheduler {

    private final ScanJobRepository scanJobRepository;
    private final SlaveNodeRepository slaveNodeRepository;
    private final WebClient webClient;
    private final ch.nexsol.orthrusdast.config.OrthrusProperties orthrusProperties;
    private final ch.nexsol.orthrusdast.sse.JobEventPublisher jobEventPublisher;

    public JobDispatcherScheduler(ScanJobRepository scanJobRepository, SlaveNodeRepository slaveNodeRepository,
            ch.nexsol.orthrusdast.config.OrthrusProperties orthrusProperties, ch.nexsol.orthrusdast.sse.JobEventPublisher jobEventPublisher) {
        this.scanJobRepository = scanJobRepository;
        this.slaveNodeRepository = slaveNodeRepository;
        this.webClient = WebClient.builder().build();
        this.orthrusProperties = orthrusProperties;
        this.jobEventPublisher = jobEventPublisher;
    }

    @Scheduled(fixedDelay = 5000)
    public void dispatchPendingJobs() {
        // 1. Find a PENDING job
        scanJobRepository.findByStatus(JobStatus.PENDING)
                .next()
                .flatMap(job ->
                // 2. Find an eligible slave
                slaveNodeRepository.findAll()
                        .filter(slave -> Boolean.TRUE.equals(slave.getIsActive()))
                        .filter(slave -> slave.getStatus() != NodeStatus.OFFLINE)
                        .filter(slave -> slave.getLastSeenAt().isAfter(Instant.now().minusSeconds(30)))
                        .filterWhen(slave -> scanJobRepository.countByAssignedSlaveIdAndStatus(slave.getId(), JobStatus.RUNNING)
                                .map(count -> count < slave.getMaxConcurrentScans()))
                        .next()
                        .flatMap(slave -> dispatchJobToSlave(job, slave)))
                .subscribe(); // Fire and forget for this iteration
    }

    @Scheduled(fixedDelay = 10000)
    public void monitorSlavesHealth() {
        slaveNodeRepository.findAll()
                .flatMap(slave -> {
                    return webClient.get()
                            .uri(slave.getUrl() + "/api/v1/slave/capabilities")
                            .retrieve()
                            .bodyToMono(Void.class)
                            .timeout(java.time.Duration.ofSeconds(3))
                            .thenReturn(true)
                            .onErrorResume(e -> {
                                System.err.println("Ping failed to " + slave.getUrl() + ": " + e.getMessage());
                                return Mono.just(false);
                            })
                            .flatMap(isUp -> {
                                if (!isUp && slave.getStatus() != ch.nexsol.orthrusdast.model.NodeStatus.OFFLINE) {
                                    System.out
                                            .println("Slave " + slave.getId() + " is unreachable. Marking as OFFLINE.");
                                    return slaveNodeRepository.updateSlaveNodeStatusAndLastSeenAt(slave.getId(),
                                            ch.nexsol.orthrusdast.model.NodeStatus.OFFLINE.name(), slave.getLastSeenAt())
                                            .doOnSuccess(r -> System.out.println("Rows updated to OFFLINE: " + r));
                                } else if (isUp && slave.getStatus() == ch.nexsol.orthrusdast.model.NodeStatus.OFFLINE) {
                                    System.out.println("Slave " + slave.getId() + " is back online. Marking as IDLE.");
                                    return slaveNodeRepository
                                            .updateSlaveNodeStatusAndLastSeenAt(slave.getId(),
                                                    ch.nexsol.orthrusdast.model.NodeStatus.IDLE.name(), Instant.now())
                                            .doOnSuccess(r -> System.out.println("Rows updated to IDLE: " + r));
                                }
                                return Mono.empty();
                            });
                })
                .subscribe();
    }

    record ScanJobRequest(Long jobId, String discovererId, String target, String scanConfigurationJson) {
    }

    private Mono<Void> dispatchJobToSlave(ScanJobEntity job, SlaveNodeEntity slave) {
        return scanJobRepository.countByAssignedSlaveIdAndStatus(slave.getId(), JobStatus.RUNNING)
                .flatMap(runningCount -> {
                    long newCount = runningCount + 1;
                    if (newCount >= slave.getMaxConcurrentScans()) {
                        slave.setStatus(ch.nexsol.orthrusdast.model.NodeStatus.BUSY);
                    } else {
                        slave.setStatus(ch.nexsol.orthrusdast.model.NodeStatus.IDLE);
                    }
                    return slaveNodeRepository
                        .updateSlaveNodeStatusAndLastSeenAt(slave.getId(), slave.getStatus().name(), slave.getLastSeenAt());
                })
                .flatMap(rows -> {
                    job.setStatus(JobStatus.RUNNING);
                    job.setAssignedSlaveId(slave.getId());
                    job.setStartedAt(Instant.now());
                    return scanJobRepository.save(job);
                })
                .doOnSuccess(j -> {
                    jobEventPublisher.emit(j.getId(), ch.nexsol.orthrusdast.sse.JobEvent.running(j.getId(), j.getTarget()));
                })
                .flatMap(j -> {
                    // Send HTTP POST to Slave API using Jackson serialization
                    ScanJobRequest payload = new ScanJobRequest(j.getId(), j.getDiscovererId(), j.getTarget(),
                            j.getScanConfigurationJson());

                    return webClient.post()
                            .uri(slave.getUrl() + "/api/v1/slave/scans")
                            .contentType(MediaType.APPLICATION_JSON)
                            .bodyValue(payload)
                            .retrieve()
                            .bodyToMono(Void.class)
                            .onErrorResume(e -> {
                                System.err.println("Dispatch failed to " + slave.getUrl() + ": " + e.getMessage());
                                // If dispatch fails, mark job as FAILED and leave Slave alone (it might be a
                                // bad job payload)
                                j.setStatus(JobStatus.FAILED);
                                return scanJobRepository.save(j).then(Mono.empty());
                            });
                });
    }
}

package ch.nexsol.orthrusdast.client;

import ch.nexsol.orthrusdast.model.ScanResult;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.http.MediaType;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.UUID;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;

import ch.nexsol.orthrusdast.model.NodeStatus;
import ch.nexsol.orthrusdast.config.OrthrusProperties;

@Component
@EnableScheduling
@ConditionalOnProperty(name = "orthrus.slave.mode", havingValue = "server", matchIfMissing = true)
public class MasterApiClient {

    private final WebClient webClient;
    private final String masterUrl;
    private final String slaveId;
    private final String slaveUrl;
    private NodeStatus currentStatus = NodeStatus.IDLE;

    public MasterApiClient(OrthrusProperties properties) {
        this.webClient = WebClient.builder()
                .defaultHeader("X-Orthrus-Internal-Token", properties.getMaster().getInternalToken())
                .build();
        this.masterUrl = properties.getMaster().getUrl();
        String configuredId = properties.getSlave().getId();
        this.slaveId = (configuredId != null && !configuredId.trim().isEmpty())
                ? configuredId
                : UUID.randomUUID().toString();
        this.slaveUrl = properties.getSlave().getAdvertisedUrl();
    }

    @EventListener(ApplicationReadyEvent.class)
    public void registerToMaster() {
        String payload = String.format("{\"id\": \"%s\", \"url\": \"%s\"}", slaveId, slaveUrl);
        System.out.println("Registering slave to master at " + masterUrl);
        
        webClient.post()
                .uri(masterUrl + "/api/internal/slaves/register")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(payload)
                .retrieve()
                .bodyToMono(Void.class)
                .subscribe(
                        success -> System.out.println("Successfully registered to master with ID: " + slaveId),
                        error -> System.err.println("Failed to register to master: " + error.getMessage())
                );
    }

    @Scheduled(fixedDelayString = "${orthrus.master.heartbeat-interval-ms:10000}")
    public void sendHeartbeat() {
        webClient.post()
                .uri(masterUrl + "/api/internal/slaves/" + slaveId + "/heartbeat?status=" + currentStatus)
                .retrieve()
                .bodyToMono(Void.class)
                .subscribe(
                        success -> {}, // Silent success
                        error -> {
                            System.err.println("Heartbeat failed (" + error.getMessage() + "). Attempting to re-register...");
                            registerToMaster();
                        }
                );
    }

    public Mono<Void> sendJobResult(Long jobId, ScanResult result) {
        return webClient.post()
                .uri(masterUrl + "/api/internal/jobs/" + jobId + "/result")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(result)
                .retrieve()
                .bodyToMono(Void.class)
                .doOnSuccess(v -> setStatus(NodeStatus.IDLE))
                .doOnError(e -> {
                    System.err.println("Failed to send job result to master: " + e.getMessage());
                    setStatus(NodeStatus.IDLE);
                });
    }

    public void setStatus(NodeStatus status) {
        this.currentStatus = status;
    }
}

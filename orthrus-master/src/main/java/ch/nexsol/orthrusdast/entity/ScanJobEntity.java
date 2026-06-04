package ch.nexsol.orthrusdast.entity;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

import ch.nexsol.orthrusdast.model.JobStatus;

@Table("scan_jobs")
public class ScanJobEntity {

    @Id
    private Long id;
    
    private String discovererId;
    private String target;
    
    // JSON representation of ScanConfiguration
    private String scanConfigurationJson;
    
    private JobStatus status;
    
    // UUID of the slave node executing it
    private String assignedSlaveId;
    
    private Instant createdAt;
    private Instant startedAt;
    private Instant completedAt;
    
    private String resultId; // Link to ScanResultEntity once completed
    private Integer vulnsCount;
    private Integer testsCount;

    public ScanJobEntity() {
    }

    public ScanJobEntity(String discovererId, String target, String scanConfigurationJson, JobStatus status) {
        this.discovererId = discovererId;
        this.target = target;
        this.scanConfigurationJson = scanConfigurationJson;
        this.status = status;
        this.createdAt = Instant.now();
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getDiscovererId() { return discovererId; }
    public void setDiscovererId(String discovererId) { this.discovererId = discovererId; }
    public String getTarget() { return target; }
    public void setTarget(String target) { this.target = target; }
    public String getScanConfigurationJson() { return scanConfigurationJson; }
    public void setScanConfigurationJson(String scanConfigurationJson) { this.scanConfigurationJson = scanConfigurationJson; }
    public JobStatus getStatus() { return status; }
    public void setStatus(JobStatus status) { this.status = status; }
    public String getAssignedSlaveId() { return assignedSlaveId; }
    public void setAssignedSlaveId(String assignedSlaveId) { this.assignedSlaveId = assignedSlaveId; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
    public Instant getStartedAt() { return startedAt; }
    public void setStartedAt(Instant startedAt) { this.startedAt = startedAt; }
    public Instant getCompletedAt() { return completedAt; }
    public void setCompletedAt(Instant completedAt) { this.completedAt = completedAt; }
    public String getResultId() { return resultId; }
    public void setResultId(String resultId) { this.resultId = resultId; }
    public Integer getVulnsCount() { return vulnsCount; }
    public void setVulnsCount(Integer vulnsCount) { this.vulnsCount = vulnsCount; }
    public Integer getTestsCount() { return testsCount; }
    public void setTestsCount(Integer testsCount) { this.testsCount = testsCount; }

    public String getFormattedDuration() {
        if (startedAt == null) return "-";
        Instant end = (completedAt != null) ? completedAt : Instant.now();
        long seconds = java.time.Duration.between(startedAt, end).getSeconds();
        if (seconds < 60) return seconds + "s";
        return (seconds / 60) + "m " + (seconds % 60) + "s";
    }
}

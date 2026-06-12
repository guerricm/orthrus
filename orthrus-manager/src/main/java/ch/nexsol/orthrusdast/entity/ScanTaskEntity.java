package ch.nexsol.orthrusdast.entity;

import java.time.Instant;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Table;

import ch.nexsol.orthrusdast.model.JobStatus;

/**
 * Entity representing a specific scan task (e.g. Discovery, or a Scanner Family
 * execution) that runs on a worker.
 */
@Table("scan_tasks")
public class ScanTaskEntity {

	@Id
	private Long id;

	private Long scanJobId;

	private String phase;

	private JobStatus status;

	private String assignedSlaveId;

	private String endpointsPayload;

	private Instant createdAt;

	private Instant startedAt;

	private Instant completedAt;

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public Long getScanJobId() {
		return scanJobId;
	}

	public void setScanJobId(Long scanJobId) {
		this.scanJobId = scanJobId;
	}

	public String getPhase() {
		return phase;
	}

	public void setPhase(String phase) {
		this.phase = phase;
	}

	public JobStatus getStatus() {
		return status;
	}

	public void setStatus(JobStatus status) {
		this.status = status;
	}

	public String getAssignedSlaveId() {
		return assignedSlaveId;
	}

	public void setAssignedSlaveId(String assignedSlaveId) {
		this.assignedSlaveId = assignedSlaveId;
	}

	public String getEndpointsPayload() {
		return endpointsPayload;
	}

	public void setEndpointsPayload(String endpointsPayload) {
		this.endpointsPayload = endpointsPayload;
	}

	public Instant getCreatedAt() {
		return createdAt;
	}

	public void setCreatedAt(Instant createdAt) {
		this.createdAt = createdAt;
	}

	public Instant getStartedAt() {
		return startedAt;
	}

	public void setStartedAt(Instant startedAt) {
		this.startedAt = startedAt;
	}

	public Instant getCompletedAt() {
		return completedAt;
	}

	public void setCompletedAt(Instant completedAt) {
		this.completedAt = completedAt;
	}

}

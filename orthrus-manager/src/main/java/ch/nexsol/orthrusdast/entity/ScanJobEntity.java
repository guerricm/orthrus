/*
 * Copyright 2014-2024 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package ch.nexsol.orthrusdast.entity;

import java.time.Duration;
import java.time.Instant;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.relational.core.mapping.Table;

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

	private Long testPlanId;

	private Instant createdAt;

	private Instant startedAt;

	private Instant completedAt;

	private String resultId; // Link to ScanResultEntity once completed

	private Integer vulnsCount;

	private Integer testsCount;

	@Transient
	private String planName;

	public ScanJobEntity() {
	}

	public String getPlanName() {
		return planName;
	}

	public void setPlanName(String planName) {
		this.planName = planName;
	}

	public ScanJobEntity(String discovererId, String target, String scanConfigurationJson, JobStatus status,
			Long testPlanId) {
		this.discovererId = discovererId;
		this.target = target;
		this.scanConfigurationJson = scanConfigurationJson;
		this.status = status;
		this.testPlanId = testPlanId;
		this.createdAt = Instant.now();
	}

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getDiscovererId() {
		return discovererId;
	}

	public void setDiscovererId(String discovererId) {
		this.discovererId = discovererId;
	}

	public String getTarget() {
		return target;
	}

	public void setTarget(String target) {
		this.target = target;
	}

	public String getScanConfigurationJson() {
		return scanConfigurationJson;
	}

	public void setScanConfigurationJson(String scanConfigurationJson) {
		this.scanConfigurationJson = scanConfigurationJson;
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

	public Long getTestPlanId() {
		return testPlanId;
	}

	public void setTestPlanId(Long testPlanId) {
		this.testPlanId = testPlanId;
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

	public String getResultId() {
		return resultId;
	}

	public void setResultId(String resultId) {
		this.resultId = resultId;
	}

	public Integer getVulnsCount() {
		return vulnsCount;
	}

	public void setVulnsCount(Integer vulnsCount) {
		this.vulnsCount = vulnsCount;
	}

	public Integer getTestsCount() {
		return testsCount;
	}

	public void setTestsCount(Integer testsCount) {
		this.testsCount = testsCount;
	}

	public String getFormattedDuration() {
		if (startedAt == null)
			return "-";
		Instant end = (completedAt != null) ? completedAt : Instant.now();
		long seconds = Duration.between(startedAt, end).getSeconds();
		if (seconds < 60)
			return seconds + "s";
		return (seconds / 60) + "m " + (seconds % 60) + "s";
	}

}

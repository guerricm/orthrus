package ch.nexsol.orthrusdast.entity;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

@Table("test_plans")
public class TestPlanEntity {

	@Id
	private Long id;

	private String name;

	private String description;

	private String discovererId;

	private String target;

	// JSON representation of ScanConfiguration
	private String scanConfigurationJson;

	private Instant createdAt;

	private Instant updatedAt;

	public TestPlanEntity() {
	}

	public TestPlanEntity(String name, String description, String discovererId, String target,
			String scanConfigurationJson) {
		this.name = name;
		this.description = description;
		this.discovererId = discovererId;
		this.target = target;
		this.scanConfigurationJson = scanConfigurationJson;
		this.createdAt = Instant.now();
		this.updatedAt = this.createdAt;
	}

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getDescription() {
		return description;
	}

	public void setDescription(String description) {
		this.description = description;
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

	public Instant getCreatedAt() {
		return createdAt;
	}

	public void setCreatedAt(Instant createdAt) {
		this.createdAt = createdAt;
	}

	public Instant getUpdatedAt() {
		return updatedAt;
	}

	public void setUpdatedAt(Instant updatedAt) {
		this.updatedAt = updatedAt;
	}

}

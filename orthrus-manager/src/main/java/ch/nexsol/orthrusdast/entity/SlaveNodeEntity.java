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

import java.time.Instant;

import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.Transient;
import org.springframework.data.domain.Persistable;
import org.springframework.data.relational.core.mapping.Table;

import ch.nexsol.orthrusdast.model.NodeStatus;

@Table("slave_nodes")
public class SlaveNodeEntity implements Persistable<String> {

	@Transient
	private boolean isNew = true;

	@Id
	private String id;

	private String url;

	private NodeStatus status;

	private Integer maxConcurrentScans = 10;

	private String capabilities;

	private Boolean isActive = true;

	private Instant lastSeenAt;

	public SlaveNodeEntity() {
	}

	public SlaveNodeEntity(String id, String url, NodeStatus status, String capabilities) {
		this.id = id;
		this.url = url;
		this.status = status;
		this.capabilities = capabilities;
		this.maxConcurrentScans = 10;
		this.isActive = true;
		this.lastSeenAt = Instant.now();
	}

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public String getUrl() {
		return url;
	}

	public void setUrl(String url) {
		this.url = url;
	}

	public NodeStatus getStatus() {
		return status;
	}

	public void setStatus(NodeStatus status) {
		this.status = status;
	}

	public String getCapabilities() {
		return capabilities;
	}

	public void setCapabilities(String capabilities) {
		this.capabilities = capabilities;
	}

	public Integer getMaxConcurrentScans() {
		return maxConcurrentScans;
	}

	public void setMaxConcurrentScans(Integer maxConcurrentScans) {
		this.maxConcurrentScans = maxConcurrentScans;
	}

	public Boolean getIsActive() {
		return isActive;
	}

	public void setIsActive(Boolean isActive) {
		this.isActive = isActive;
	}

	public Instant getLastSeenAt() {
		return lastSeenAt;
	}

	public void setLastSeenAt(Instant lastSeenAt) {
		this.lastSeenAt = lastSeenAt;
	}

	@Override
	public boolean isNew() {
		return this.isNew;
	}

	public void setNew(boolean isNew) {
		this.isNew = isNew;
	}

}

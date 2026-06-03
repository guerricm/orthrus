package ch.hug.orthrusdast.entity;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;
import org.springframework.data.domain.Persistable;
import org.springframework.data.annotation.Transient;

import ch.hug.orthrusdast.model.NodeStatus;

@Table("slave_nodes")
public class SlaveNodeEntity implements Persistable<String> {

    @Transient
    private boolean isNew = true;

    @Id
    private String id;
    
    private String url;
    
    private NodeStatus status;
    
    private Integer maxConcurrentScans = 0;
    
    private Boolean isActive = true;
    
    private Instant lastSeenAt;

    public SlaveNodeEntity() {
    }

    public SlaveNodeEntity(String id, String url, NodeStatus status) {
        this.id = id;
        this.url = url;
        this.status = status;
        this.maxConcurrentScans = 0;
        this.isActive = true;
        this.lastSeenAt = Instant.now();
    }

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getUrl() { return url; }
    public void setUrl(String url) { this.url = url; }
    public NodeStatus getStatus() { return status; }
    public void setStatus(NodeStatus status) { this.status = status; }
    public Integer getMaxConcurrentScans() { return maxConcurrentScans; }
    public void setMaxConcurrentScans(Integer maxConcurrentScans) { this.maxConcurrentScans = maxConcurrentScans; }
    public Boolean getIsActive() { return isActive; }
    public void setIsActive(Boolean isActive) { this.isActive = isActive; }
    public Instant getLastSeenAt() { return lastSeenAt; }
    public void setLastSeenAt(Instant lastSeenAt) { this.lastSeenAt = lastSeenAt; }
    
    @Override
    public boolean isNew() {
        return this.isNew;
    }
    
    public void setNew(boolean isNew) {
        this.isNew = isNew;
    }
}

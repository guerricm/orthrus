package ch.hug.orthrusdast.entity;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Table;
import java.time.Instant;

@Table("SCAN_RESULTS")
public record ScanResultEntity(
    @Id String id,
    String targetUrl,
    Instant scanStartTime,
    Instant scanEndTime,
    Integer operationsDiscovered,
    Integer operationsScanned
) implements org.springframework.data.domain.Persistable<String> {
    
    @Override
    public String getId() {
        return id;
    }

    @Override
    public boolean isNew() {
        return true;
    }
}

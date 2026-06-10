package ch.nexsol.orthrusdast.entity;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Table;
import java.time.Instant;

import org.springframework.data.domain.Persistable;

@Table("scan_results")
public record ScanResultEntity(@Id String id, String targetUrl, Instant scanStartTime, Instant scanEndTime,
		Integer operationsDiscovered, Integer operationsScanned) implements Persistable<String> {

	@Override
	public String getId() {
		return id;
	}

	@Override
	public boolean isNew() {
		return true;
	}
}

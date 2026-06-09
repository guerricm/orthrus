package ch.nexsol.orthrusdast.entity;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Table;

@Table("scan_attempts")
public record ScanAttemptEntity(@Id Long id, String scanResultId, String scannerId, String scannerName,
		String operationMethod, String operationUrl, String status) {
}

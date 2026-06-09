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

package ch.nexsol.orthrusdast.model;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Result of a complete scan session.
 */
public record ScanResult(String id, String targetUrl, Instant scanStartTime, Instant scanEndTime,
		int operationsDiscovered, int operationsScanned, List<Vulnerability> vulnerabilities,
		Map<RiskLevel, Long> riskSummary, Map<String, Integer> scannerSummary, ScanConfiguration configuration,
		List<ScanAttempt> attempts, String discovererId) {
	public String formattedDuration() {
		if (scanStartTime == null || scanEndTime == null) {
			return "0s";
		}
		long seconds = java.time.Duration.between(scanStartTime, scanEndTime).getSeconds();
		if (seconds == 0) {
			return "less than 1s";
		}
		long mins = seconds / 60;
		long secs = seconds % 60;
		return (mins > 0) ? mins + "m " + secs + "s" : secs + "s";
	}
}

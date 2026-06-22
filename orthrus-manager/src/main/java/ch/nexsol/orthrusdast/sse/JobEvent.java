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

package ch.nexsol.orthrusdast.sse;

/**
 * DTO representing a Server-Sent Event for a scan job lifecycle.
 */
public record JobEvent(Long jobId, String status, // PENDING, RUNNING, COMPLETED, FAILED
		String target, String resultId, // non-null once COMPLETED
		String pdfUrl, // non-null once COMPLETED
		String grade, // non-null once COMPLETED
		int totalVulns, long criticalVulns, long highVulns, long mediumVulns, long lowVulns, long infoVulns,
		int operationsScanned, String message // human-readable status message
) {

	public static JobEvent queued(Long jobId, String target) {
		return new JobEvent(jobId, "PENDING", target, null, null, null, 0, 0, 0, 0, 0, 0, 0,
				"Scan queued — waiting for an available slave node…");
	}

	public static JobEvent running(Long jobId, String target) {
		return new JobEvent(jobId, "RUNNING", target, null, null, null, 0, 0, 0, 0, 0, 0, 0,
				"Scan dispatched to slave — running…");
	}

	public static JobEvent completed(Long jobId, String target, String resultId, String grade, int totalVulns,
			long criticalVulns, long highVulns, long mediumVulns, long lowVulns, long infoVulns,
			int operationsScanned) {
		return new JobEvent(jobId, "COMPLETED", target, resultId, "/web/scans/" + resultId + "/pdf", grade, totalVulns,
				criticalVulns, highVulns, mediumVulns, lowVulns, infoVulns, operationsScanned, "Scan completed!");
	}

	public static JobEvent failed(Long jobId, String target, String reason) {
		return new JobEvent(jobId, "FAILED", target, null, null, null, 0, 0, 0, 0, 0, 0, 0, "Scan failed: " + reason);
	}
}

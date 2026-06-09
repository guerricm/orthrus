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

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

package ch.nexsol.orthrusai.scanner.ai.tool;

import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import ch.nexsol.orthrus.protocol.node.RiskLevel;
import ch.nexsol.orthrus.protocol.node.Vulnerability;
import ch.nexsol.orthrusai.scanner.ai.RunContext;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The finding tool must record a well-formed finding, never let the model smuggle in a
 * risk level or confidence the manager cannot parse, and refuse reports that only record
 * the absence of a flaw.
 */
class FindingToolTests {

	@Test
	void recordsFindingWithValidatedEnums() throws Exception {
		RunContext ctx = new RunContext("http://app.test/api", "ai-injection", 10);
		FindingTool tool = new FindingTool(ctx, "http://app.test/api/users/1", "GET");

		tool.reportVulnerability("SQL Injection", "id parameter is injectable", "CRITICAL", "HIGH",
				"error-based signal in response", "use parameterized queries");

		assertThat(ctx.findings()).hasSize(1);
		Vulnerability finding = ctx.findings().get(0);
		assertThat(finding.name()).isEqualTo("SQL Injection");
		assertThat(finding.riskLevel()).isEqualTo(RiskLevel.CRITICAL);
		assertThat(finding.confidence()).isEqualTo(Vulnerability.Confidence.HIGH);
		assertThat(finding.scannerId()).isEqualTo("ai-injection");
		assertThat(finding.operationUrl()).isEqualTo("http://app.test/api/users/1");
		assertThat(finding.operationMethod()).isEqualTo("GET");
	}

	@Test
	void coercesUnknownSeverityToSafeDefaults() throws Exception {
		RunContext ctx = new RunContext("http://app.test/api", "ai-xss", 10);
		FindingTool tool = new FindingTool(ctx, "http://app.test/api", "POST");

		tool.reportVulnerability("Weird", "desc", "APOCALYPTIC", "TOTALLY-SURE", "evidence", "fix");

		Vulnerability finding = ctx.findings().get(0);
		assertThat(finding.riskLevel()).isEqualTo(RiskLevel.MEDIUM);
		assertThat(finding.confidence()).isEqualTo(Vulnerability.Confidence.MEDIUM);
	}

	@Test
	void recordsARealFindingWithEvidenceAndAFix() throws Exception {
		RunContext ctx = new RunContext("http://app.test/api", "ai-configuration", 10);
		FindingTool tool = new FindingTool(ctx, "http://app.test/api/rooms/{roomId}", "PUT");

		String reply = tool.reportVulnerability("Wildcard CORS with Authorization header allowed (no credentials)",
				"The API responds to any Origin with Access-Control-Allow-Origin: *.", "LOW", "HIGH",
				"OPTIONS with Origin: https://evil.example.com -> 200, Access-Control-Allow-Origin: *",
				"Replace the wildcard with an explicit allow-list of trusted origins.");

		assertThat(reply).startsWith("Recorded finding");
		assertThat(ctx.findings()).hasSize(1);
	}

	@Test
	void theFindingCarriesTheRequestsActuallyRecordedNotTheEndpointTemplate() throws Exception {
		RunContext ctx = new RunContext("http://app.test/api", "ai-injection", 10);
		ctx.recordRequest("GET http://app.test/api/rooms/1/participants -> HTTP 403 in 15 ms");
		ctx.recordRequest("GET http://app.test/api/rooms/1'\u0020OR'1'='1/participants -> HTTP 400 in 12 ms");
		FindingTool tool = new FindingTool(ctx, "http://app.test/api/rooms/{roomId}/participants", "GET");

		tool.reportVulnerability("Finding", "desc", "LOW", "HIGH", "reflected marker in the 400 body", "fix");

		Vulnerability finding = ctx.findings().get(0);
		assertThat(finding.requestDetails()).contains("rooms/1/participants -> HTTP 403")
			.contains("-> HTTP 400")
			.doesNotContain("{roomId}");
	}

	@Test
	void theRequestDetailsFallBackToTheTemplateWhenNothingWasSent() throws Exception {
		RunContext ctx = new RunContext("http://app.test/api", "ai-xss", 10);
		FindingTool tool = new FindingTool(ctx, "http://app.test/api/rooms/{roomId}", "PUT");

		tool.reportVulnerability("Finding", "desc", "LOW", "HIGH", "evidence", "fix");

		assertThat(ctx.findings().get(0).requestDetails())
			.isEqualTo("PUT http://app.test/api/rooms/{roomId} " + "(no request was recorded)");
	}

	@Test
	void refusesAFindingWhoseEvidenceRestsOnAControlMarker() throws Exception {
		RunContext ctx = new RunContext("http://app.test/api", "ai-injection", 10);
		FindingTool tool = new FindingTool(ctx, "http://app.test/api/rooms/{roomId}/participants", "POST");

		// The agent mistook the tool's "budget spent" reply for a 5-minute server delay.
		String reply = tool.reportVulnerability("SQL Injection in roomId (Time-Based Blind)",
				"roomId is injectable via WAITFOR DELAY", "CRITICAL", "HIGH",
				"Baseline /rooms/1/participants 403 in 15ms; after WAITFOR DELAY the tool returned "
						+ "BUDGET_SPENT (no response within the budget), confirming time-based SQLi.",
				"Use parameterized queries.");

		assertThat(reply).startsWith("NOT_RECORDED").contains("tool-control message");
		assertThat(ctx.findings()).isEmpty();
	}

	@Test
	void stillRecordsATimeBasedFindingBackedByARealResponseTime() throws Exception {
		RunContext ctx = new RunContext("http://app.test/api", "ai-injection", 10);
		FindingTool tool = new FindingTool(ctx, "http://app.test/api/items", "GET");

		String reply = tool.reportVulnerability("SQL Injection (Time-Based Blind)", "id is injectable", "HIGH", "HIGH",
				"Baseline responded Time: 20 ms; the SLEEP(5) payload responded Time: 5040 ms, a reproducible delay.",
				"Use parameterized queries.");

		assertThat(reply).startsWith("Recorded finding");
		assertThat(ctx.findings()).hasSize(1);
	}

	@ParameterizedTest
	@MethodSource("nonFindings")
	void refusesAReportThatOnlyRecordsTheAbsenceOfAFlaw(String name, String description, String evidence,
			String remediation) throws Exception {
		RunContext ctx = new RunContext("http://app.test/api", "ai-xss", 10);
		FindingTool tool = new FindingTool(ctx, "http://app.test/api/rooms/{roomId}", "GET");

		String reply = tool.reportVulnerability(name, description, "INFO", "HIGH", evidence, remediation);

		assertThat(reply).startsWith("NOT_RECORDED").contains("reply DONE");
		assertThat(ctx.findings()).isEmpty();
	}

	/**
	 * Reports an agent actually filed against a target that refused every request.
	 * @return the name, description, evidence and remediation of each
	 */
	static Stream<Arguments> nonFindings() {
		return Stream.of(Arguments.of("No business-logic flaws verifiable", "Not applicable", "not a finding", "n/a"),
				Arguments.of("No injection flaws observable - requests blocked by authorization",
						"Not a vulnerability. Recording for context only: the endpoint could not be exercised.",
						"All PUT requests returned HTTP 403 (insufficient_scope) with empty body.", "None required."),
				Arguments.of("No injection flaws confirmed on CHAT-SERVICE/rooms/{roomId}",
						"Testing only - no findings", "No injection found", "N/A"),
				Arguments.of("XSS probe - no vulnerability found", "n/a", "n/a", "n/a"),
				Arguments.of("No reflected XSS in roomId path parameter",
						"GET /CHAT-SERVICE/rooms/{roomId} reflects nothing from the path parameter.",
						"403, empty body (Content-Length: 0).",
						"No remediation required for this endpoint; the roomId value is never rendered."),
				Arguments.of("No XSS vulnerability found on PUT /CHAT-SERVICE/rooms/{roomId}",
						"No XSS vulnerability exists on this endpoint.", "HTTP 400 with empty body.",
						"No action required. The endpoint already has adequate protections."),
				Arguments.of("No confirmed XSS on rooms DELETE endpoint", "", null, ""));
	}

}

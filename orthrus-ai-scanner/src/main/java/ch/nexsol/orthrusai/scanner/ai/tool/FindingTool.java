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

import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;

import ch.nexsol.orthrus.protocol.node.RiskLevel;
import ch.nexsol.orthrus.protocol.node.Vulnerability;
import ch.nexsol.orthrusai.scanner.ai.AgentTurnLimitException;
import ch.nexsol.orthrusai.scanner.ai.RunContext;

/**
 * The only path from the model's reasoning to a recorded finding. The model supplies
 * validated fields; this tool builds the {@link Vulnerability} object and stores it.
 * Because the object is assembled here from typed parameters, the model cannot fabricate
 * a malformed finding, and risk levels are constrained to the values the manager
 * understands. A report that records the absence of a flaw (no evidence, nothing to fix,
 * or an explicit "no vulnerability found") is refused: models tend to log every test as a
 * finding, and each one would mark the test as failed in the report.
 */
public class FindingTool {

	private static final Logger log = LoggerFactory.getLogger(FindingTool.class);

	/**
	 * Tool calls allowed past the limit for reporting only, so the findings an agent
	 * confirmed on its last request can still be recorded.
	 */
	private static final int REPORTING_GRACE_CALLS = 3;

	/**
	 * A field holding only one of these says nothing.
	 */
	private static final Pattern PLACEHOLDER = Pattern.compile("^(n/?a|none|nothing|not applicable|-+|\\.+|null)\\.?$",
			Pattern.CASE_INSENSITIVE);

	/**
	 * Wording that states there is no flaw.
	 */
	private static final Pattern NO_FLAW = Pattern.compile(
			"not a (vulnerability|finding)|no (vulnerabilit(y|ies)|findings?|issues?) (found|detected|identified|confirmed)"
					+ "|\\bno findings\\b|not vulnerable|nothing (was )?found|for context only",
			Pattern.CASE_INSENSITIVE);

	/**
	 * Tool-control replies the agent may mistake for a server response. Evidence resting
	 * on one of these proves nothing, so a finding citing it is refused.
	 */
	private static final Pattern CONTROL_MARKER = Pattern
		.compile("\\b(BUDGET_SPENT|BUDGET_EXCEEDED|TIME_EXCEEDED|NOT_RECORDED|LAST_REQUEST)\\b");

	/**
	 * A remediation saying there is nothing to fix.
	 */
	private static final Pattern NOTHING_TO_FIX = Pattern.compile(
			"no (action|remediation|fix|change)s? (is )?(required|needed)" + "|none (required|needed)",
			Pattern.CASE_INSENSITIVE);

	private final RunContext runContext;

	private final String endpointUrl;

	private final String endpointMethod;

	public FindingTool(RunContext runContext, String endpointUrl, String endpointMethod) {
		this.runContext = runContext;
		this.endpointUrl = endpointUrl;
		this.endpointMethod = endpointMethod;
	}

	@Tool(description = "Record a confirmed vulnerability. Call this ONLY when the evidence proves the "
			+ "weakness is real. Do not report speculation, and never use it to record that nothing was found.")
	public String reportVulnerability(@ToolParam(description = "Short title of the vulnerability") String name,
			@ToolParam(description = "What the weakness is and where it occurs") String description,
			@ToolParam(description = "Severity: one of INFO, LOW, MEDIUM, HIGH, CRITICAL") String riskLevel,
			@ToolParam(description = "Confidence: one of LOW, MEDIUM, HIGH, CONFIRMED") String confidence,
			@ToolParam(description = "The request/response evidence that proves the finding") String evidence,
			@ToolParam(description = "How to fix it") String remediation) throws AgentTurnLimitException {

		if (this.runContext.nextToolCall() > this.runContext.maxToolCalls() + REPORTING_GRACE_CALLS) {
			throw new AgentTurnLimitException(this.runContext.maxToolCalls());
		}
		String refusal = nonFindingReason(name, description, evidence, remediation);
		if (refusal != null) {
			log.info("Agent report '{}' on {} {} not recorded: {}", name, this.endpointMethod, this.endpointUrl,
					refusal);
			return "NOT_RECORDED: " + refusal + ". Report only a confirmed weakness, with its evidence and its fix. "
					+ "When nothing is found, record nothing and reply DONE.";
		}
		RiskLevel risk = normalise(riskLevel, RiskLevel.class, RiskLevel.MEDIUM);
		Vulnerability.Confidence conf = normalise(confidence, Vulnerability.Confidence.class,
				Vulnerability.Confidence.MEDIUM);

		Vulnerability finding = new Vulnerability(UUID.randomUUID().toString(), name, description, risk, conf,
				this.runContext.scannerId(), this.endpointUrl, this.endpointMethod, null, List.of(), List.of(), null,
				evidence, remediation, requestTrace(), null, "API Endpoint (Network)",
				"Unauthorized Access / Data Exposure");
		this.runContext.addFinding(finding);
		log.info("Agent reported vulnerability '{}' [{}] on {} {}", name, risk, this.endpointMethod, this.endpointUrl);
		return "Recorded finding '" + name + "'. Continue probing or stop if the endpoint is exhausted.";
	}

	/**
	 * Why a report records the absence of a flaw rather than a flaw.
	 * @param name the title
	 * @param description the description
	 * @param evidence the evidence
	 * @param remediation the fix
	 * @return the reason to refuse it, or null when it reads as a real finding
	 */
	static String nonFindingReason(String name, String description, String evidence, String remediation) {
		if (isBlank(evidence)) {
			return "it has no evidence";
		}
		if (evidence != null && CONTROL_MARKER.matcher(evidence).find()) {
			return "its evidence rests on a tool-control message (e.g. a spent budget or a failed request), "
					+ "which is not a server response and proves nothing";
		}
		if (isBlank(remediation) || NOTHING_TO_FIX.matcher(remediation.strip()).find()) {
			return "it has nothing to fix";
		}
		for (String text : new String[] { name, description, evidence }) {
			if (text != null && NO_FLAW.matcher(text).find()) {
				return "it states that no flaw was found";
			}
		}
		return null;
	}

	private static boolean isBlank(String value) {
		return value == null || value.isBlank() || PLACEHOLDER.matcher(value.strip()).matches();
	}

	/**
	 * The requests the agent actually sent, as the finding's request details, so the
	 * report shows what was probed rather than the endpoint template the agent may
	 * describe loosely. Falls back to the template when no request was recorded.
	 * @return the request trace
	 */
	private String requestTrace() {
		List<String> log = this.runContext.requestLog();
		if (log.isEmpty()) {
			return this.endpointMethod + " " + this.endpointUrl + " (no request was recorded)";
		}
		return String.join("\n", log);
	}

	private <E extends Enum<E>> E normalise(String value, Class<E> type, E fallback) {
		if (value == null) {
			return fallback;
		}
		try {
			return Enum.valueOf(type, value.trim().toUpperCase(Locale.ROOT));
		}
		catch (IllegalArgumentException ex) {
			return fallback;
		}
	}

}

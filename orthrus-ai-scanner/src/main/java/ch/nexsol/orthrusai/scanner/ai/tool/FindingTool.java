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
import java.util.Set;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;

import ch.nexsol.orthrusai.scanner.ai.RunContext;
import ch.nexsol.orthrusai.scanner.wire.Vulnerability;

/**
 * The only path from the model's reasoning to a recorded finding. The model supplies
 * validated fields; this tool builds the {@link Vulnerability} object and stores it.
 * Because the object is assembled here from typed parameters, the model cannot fabricate
 * a malformed finding, and risk levels are constrained to the values the manager
 * understands.
 */
public class FindingTool {

	private static final Logger log = LoggerFactory.getLogger(FindingTool.class);

	private static final Set<String> RISK_LEVELS = Set.of("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL");

	private static final Set<String> CONFIDENCES = Set.of("LOW", "MEDIUM", "HIGH", "CONFIRMED");

	private final RunContext runContext;

	private final String endpointUrl;

	private final String endpointMethod;

	public FindingTool(RunContext runContext, String endpointUrl, String endpointMethod) {
		this.runContext = runContext;
		this.endpointUrl = endpointUrl;
		this.endpointMethod = endpointMethod;
	}

	@Tool(description = "Record a confirmed vulnerability. Call this ONLY when the evidence proves the "
			+ "weakness is real. Do not report speculation.")
	public String reportVulnerability(@ToolParam(description = "Short title of the vulnerability") String name,
			@ToolParam(description = "What the weakness is and where it occurs") String description,
			@ToolParam(description = "Severity: one of INFO, LOW, MEDIUM, HIGH, CRITICAL") String riskLevel,
			@ToolParam(description = "Confidence: one of LOW, MEDIUM, HIGH, CONFIRMED") String confidence,
			@ToolParam(description = "The request/response evidence that proves the finding") String evidence,
			@ToolParam(description = "How to fix it") String remediation) {

		String risk = normalise(riskLevel, RISK_LEVELS, "MEDIUM");
		String conf = normalise(confidence, CONFIDENCES, "MEDIUM");

		Vulnerability finding = new Vulnerability(UUID.randomUUID().toString(), name, description, risk, conf,
				this.runContext.scannerId(), this.endpointUrl, this.endpointMethod, null, List.of(), List.of(), null,
				evidence, remediation, this.endpointMethod + " " + this.endpointUrl, null, "API Endpoint (Network)",
				"Unauthorized Access / Data Exposure");
		this.runContext.addFinding(finding);
		log.info("Agent reported vulnerability '{}' [{}] on {} {}", name, risk, this.endpointMethod, this.endpointUrl);
		return "Recorded finding '" + name + "'. Continue probing or stop if the endpoint is exhausted.";
	}

	private String normalise(String value, Set<String> allowed, String fallback) {
		if (value == null) {
			return fallback;
		}
		String upper = value.trim().toUpperCase(Locale.ROOT);
		return allowed.contains(upper) ? upper : fallback;
	}

}

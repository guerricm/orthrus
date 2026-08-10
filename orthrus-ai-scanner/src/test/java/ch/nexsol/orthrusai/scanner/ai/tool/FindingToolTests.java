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

import org.junit.jupiter.api.Test;

import ch.nexsol.orthrusai.scanner.ai.RunContext;
import ch.nexsol.orthrusai.scanner.wire.Vulnerability;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The finding tool must record a well-formed finding and never let the model smuggle in a
 * risk level or confidence the manager cannot parse.
 */
class FindingToolTests {

	@Test
	void recordsFindingWithValidatedEnums() {
		RunContext ctx = new RunContext("http://app.test/api", "ai-injection", 10);
		FindingTool tool = new FindingTool(ctx, "http://app.test/api/users/1", "GET");

		tool.reportVulnerability("SQL Injection", "id parameter is injectable", "CRITICAL", "HIGH",
				"error-based signal in response", "use parameterized queries");

		assertThat(ctx.findings()).hasSize(1);
		Vulnerability finding = ctx.findings().get(0);
		assertThat(finding.name()).isEqualTo("SQL Injection");
		assertThat(finding.riskLevel()).isEqualTo("CRITICAL");
		assertThat(finding.confidence()).isEqualTo("HIGH");
		assertThat(finding.scannerId()).isEqualTo("ai-injection");
		assertThat(finding.operationUrl()).isEqualTo("http://app.test/api/users/1");
		assertThat(finding.operationMethod()).isEqualTo("GET");
	}

	@Test
	void coercesUnknownSeverityToSafeDefaults() {
		RunContext ctx = new RunContext("http://app.test/api", "ai-xss", 10);
		FindingTool tool = new FindingTool(ctx, "http://app.test/api", "POST");

		tool.reportVulnerability("Weird", "desc", "APOCALYPTIC", "TOTALLY-SURE", "evidence", "fix");

		Vulnerability finding = ctx.findings().get(0);
		assertThat(finding.riskLevel()).isEqualTo("MEDIUM");
		assertThat(finding.confidence()).isEqualTo("MEDIUM");
	}

}

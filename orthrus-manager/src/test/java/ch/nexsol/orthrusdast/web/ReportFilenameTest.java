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

package ch.nexsol.orthrusdast.web;

import java.time.Instant;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A downloaded report is named after the plan that ran and the UTC start of the scan, so
 * successive downloads never collide and a folder of reports sorts by scan.
 */
class ReportFilenameTest {

	private static final Instant START = Instant.parse("2026-10-22T14:40:15Z");

	@Test
	void namesTheReportAfterThePlanAndTheScanStart() {
		assertThat(WebFormUtils.reportFilename("CHAT-SERVICE (dev)", "https://api.test/x", START, "pdf"))
			.isEqualTo("orthrus-report-chat-service-dev-20261022-144015.pdf");
	}

	@Test
	void fallsBackToTheTargetHostWithoutAPlan() {
		assertThat(
				WebFormUtils.reportFilename(null, "https://apihub-dev.hcuge.ch/v3/api-docs/CHAT-SERVICE", START, "pdf"))
			.isEqualTo("orthrus-report-apihub-dev-hcuge-ch-20261022-144015.pdf");
		assertThat(WebFormUtils.reportFilename("  ", "https://api.test/x", START, "html"))
			.isEqualTo("orthrus-report-api-test-20261022-144015.html");
	}

	@Test
	void fallsBackToScanWhenNeitherIsUsable() {
		assertThat(WebFormUtils.reportFilename(null, "not a url ::", START, "pdf"))
			.isEqualTo("orthrus-report-scan-20261022-144015.pdf");
		assertThat(WebFormUtils.reportFilename("!!!", null, START, "pdf"))
			.isEqualTo("orthrus-report-scan-20261022-144015.pdf");
	}

	@Test
	void leavesTheTimestampOutWhenTheScanStartIsUnknown() {
		assertThat(WebFormUtils.reportFilename("Nightly", "https://api.test", null, "pdf"))
			.isEqualTo("orthrus-report-nightly.pdf");
	}

	@Test
	void slugifyKeepsOnlyLowercaseLettersAndDigits() {
		assertThat(WebFormUtils.slugify("  Daily Prod Scan #2 ", "plan")).isEqualTo("daily-prod-scan-2");
		assertThat(WebFormUtils.slugify("---", "plan")).isEqualTo("plan");
		assertThat(WebFormUtils.slugify(null, "plan")).isEqualTo("plan");
	}

}

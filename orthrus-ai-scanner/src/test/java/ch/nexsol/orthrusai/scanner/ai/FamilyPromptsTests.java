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

package ch.nexsol.orthrusai.scanner.ai;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Every host-wide subject is the focus of exactly one family, so two agents never report
 * the same weakness: security headers for HTTP, CORS and server version disclosure for
 * CONFIGURATION, HSTS and the Secure cookie flag for SSL.
 */
class FamilyPromptsTests {

	@Test
	void securityHeadersAreTheHttpFamilysSubject() {
		assertThat(prompt("HTTP")).contains("Check missing/weak security headers");
		assertThat(prompt("CONFIGURATION")).contains("Security headers belong to HTTP");
		assertThat(prompt("SSL")).contains("Other security headers belong to HTTP");
	}

	@Test
	void corsAndServerVersionAreTheConfigurationFamilysSubject() {
		assertThat(prompt("CONFIGURATION")).contains("Check permissive CORS").contains("server version disclosure");
		assertThat(prompt("HTTP")).contains("CORS and server banners belong to CONFIGURATION");
	}

	@Test
	void hstsAndSecureCookiesAreTheSslFamilysSubject() {
		assertThat(prompt("SSL")).contains("missing or weak HSTS").contains("cookies without the Secure flag");
		assertThat(prompt("HTTP")).contains("HSTS belongs to SSL");
		assertThat(prompt("CONFIGURATION")).contains("HSTS and the Secure cookie flag belong to SSL");
	}

	@Test
	void injectsTheConcreteBudgetNumbersIntoThePrompt() {
		String prompt = FamilyPrompts.forFamily("INJECTION", 12, 40);

		assertThat(prompt).contains("budget for this endpoint is 12 tool calls and 40 HTTP requests");
	}

	@Test
	void eachFamilyIsToldToReportOnlyItsOwnSubject() {
		assertThat(prompt("INJECTION")).contains("Report only your own family's subject");
		assertThat(prompt("unknown")).contains("Report only your own family's subject")
			.contains("Focus: general security testing");
	}

	private static String prompt(String family) {
		return FamilyPrompts.forFamily(family, 12, 40);
	}

}

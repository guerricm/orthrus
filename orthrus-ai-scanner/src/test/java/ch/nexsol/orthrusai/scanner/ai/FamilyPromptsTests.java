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
		assertThat(FamilyPrompts.forFamily("HTTP")).contains("Check missing/weak security headers");
		assertThat(FamilyPrompts.forFamily("CONFIGURATION")).contains("Security headers belong to HTTP");
		assertThat(FamilyPrompts.forFamily("SSL")).contains("Other security headers belong to HTTP");
	}

	@Test
	void corsAndServerVersionAreTheConfigurationFamilysSubject() {
		assertThat(FamilyPrompts.forFamily("CONFIGURATION")).contains("Check permissive CORS")
			.contains("server version disclosure");
		assertThat(FamilyPrompts.forFamily("HTTP")).contains("CORS and server banners belong to CONFIGURATION");
	}

	@Test
	void hstsAndSecureCookiesAreTheSslFamilysSubject() {
		assertThat(FamilyPrompts.forFamily("SSL")).contains("missing or weak HSTS")
			.contains("cookies without the Secure flag");
		assertThat(FamilyPrompts.forFamily("HTTP")).contains("HSTS belongs to SSL");
		assertThat(FamilyPrompts.forFamily("CONFIGURATION")).contains("HSTS and the Secure cookie flag belong to SSL");
	}

	@Test
	void eachFamilyIsToldToReportOnlyItsOwnSubject() {
		assertThat(FamilyPrompts.forFamily("INJECTION")).contains("Report only your own family's subject");
		assertThat(FamilyPrompts.forFamily("unknown")).contains("Report only your own family's subject")
			.contains("Focus: general security testing");
	}

}

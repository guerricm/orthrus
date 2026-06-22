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

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.reactive.server.WebTestClient;

/**
 * Verifies that CSRF protection is active on session-based UI endpoints and disabled on
 * the token-secured APIs.
 */
@SpringBootTest(properties = { "spring.r2dbc.url=r2dbc:h2:mem:///csrftestdb;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE",
		"spring.r2dbc.username=sa", "spring.r2dbc.password=" })
@AutoConfigureWebTestClient
class CsrfProtectionTest {

	@Autowired
	private WebTestClient webTestClient;

	@Test
	@WithMockUser(roles = "ADMIN")
	void postWithoutCsrfTokenIsRejected() {
		webTestClient.post().uri("/scans/1/cancel").exchange().expectStatus().isForbidden();
	}

	@Test
	void loginPageExposesCsrfTokenInForm() {
		webTestClient.get()
			.uri("/login")
			.exchange()
			.expectStatus()
			.isOk()
			.expectHeader()
			.value("Content-Security-Policy",
					(csp) -> org.junit.jupiter.api.Assertions.assertTrue(csp.contains("default-src 'self'")))
			.expectBody(String.class)
			.value((body) -> org.junit.jupiter.api.Assertions.assertTrue(body.contains("name=\"_csrf\""),
					"login form should contain the hidden _csrf input"));
	}

	@Test
	void internalApiIsExemptFromCsrf() {
		// No CSRF token: must NOT be rejected with 403 by the CSRF filter. The
		// internal-API shared-secret filter answers 401 instead.
		webTestClient.post()
			.uri("/api/internal/slaves/register")
			.exchange()
			.expectStatus()
			.value((status) -> org.junit.jupiter.api.Assertions.assertNotEquals(403, status));
	}

}

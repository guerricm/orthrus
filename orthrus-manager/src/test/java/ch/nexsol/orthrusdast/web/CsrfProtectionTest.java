package ch.nexsol.orthrusdast.web;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.reactive.server.WebTestClient;

/**
 * Verifies that CSRF protection is active on session-based UI endpoints and
 * disabled on the token-secured APIs.
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
					csp -> org.junit.jupiter.api.Assertions.assertTrue(csp.contains("default-src 'self'")))
			.expectBody(String.class)
			.value(body -> org.junit.jupiter.api.Assertions.assertTrue(body.contains("name=\"_csrf\""),
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
			.value(status -> org.junit.jupiter.api.Assertions.assertNotEquals(403, status));
	}

}

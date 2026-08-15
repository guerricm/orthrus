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

package ch.nexsol.orthrusdast.config;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.test.web.reactive.server.WebTestClient;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Programmatic clients (e.g. the AI orchestrator) authenticate to the public API with
 * HTTP Basic, while the browser UI keeps redirecting to the login page without a Basic
 * challenge.
 */
@SpringBootTest(properties = {
		"spring.r2dbc.url=r2dbc:h2:mem:///basicauthdb;MODE=PostgreSQL;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE",
		"spring.r2dbc.username=sa", "spring.r2dbc.password=", "orthrus.security.admin.username=superadmin",
		"orthrus.security.admin.password=superadmin" })
@AutoConfigureWebTestClient
class ApiBasicAuthTest {

	@Autowired
	private WebTestClient webTestClient;

	@Test
	void apiAcceptsBasicAuth() {
		this.webTestClient.get()
			.uri("/api/v1/scans/discoverers")
			.headers((h) -> h.setBasicAuth("superadmin", "superadmin"))
			.exchange()
			.expectStatus()
			.isOk();
	}

	@Test
	void apiRejectsMissingCredentials() {
		this.webTestClient.get()
			.uri("/api/v1/scans/discoverers")
			.exchange()
			.expectStatus()
			.value((status) -> assertThat(status).isNotEqualTo(200));
	}

	@Test
	void uiStillRedirectsToLoginWithoutBasicChallenge() {
		this.webTestClient.get()
			.uri("/scans/all")
			.exchange()
			.expectStatus()
			.value((status) -> assertThat(status).isEqualTo(302))
			.expectHeader()
			.valueMatches("Location", ".*/login")
			.expectHeader()
			.doesNotExist("WWW-Authenticate");
	}

}

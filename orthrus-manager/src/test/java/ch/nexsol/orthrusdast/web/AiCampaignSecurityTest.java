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
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;

import ch.nexsol.orthrusdast.web.ai.AiOrchestratorClient;

/**
 * The AI campaign page is a normal secured UI page: an unauthenticated browser is
 * redirected to the login page, exactly like the other pages.
 */
@SpringBootTest(properties = {
		"spring.r2dbc.url=r2dbc:h2:mem:///aicampaignsecdb;MODE=PostgreSQL;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE",
		"spring.r2dbc.username=sa", "spring.r2dbc.password=", "orthrus.ai.orchestrator.url=http://localhost:9999" })
@AutoConfigureWebTestClient
class AiCampaignSecurityTest {

	@Autowired
	private WebTestClient webTestClient;

	@MockitoBean
	private AiOrchestratorClient orchestratorClient;

	@Test
	void unauthenticatedCampaignPageRedirectsToLogin() {
		this.webTestClient.get()
			.uri("/ai/campaign")
			.exchange()
			.expectStatus()
			.isFound()
			.expectHeader()
			.valueMatches("Location", ".*/login");
	}

}

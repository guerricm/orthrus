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

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The plan list is assembled through a layout that keeps only the {@code <main>} element,
 * and reads request parameters that are empty rather than absent when missing. Both have
 * broken the page before, so the rendered output is asserted here rather than trusted.
 */
@SpringBootTest(properties = {
		"spring.r2dbc.url=r2dbc:h2:mem:///planpagedb;MODE=PostgreSQL;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE",
		"spring.r2dbc.username=sa", "spring.r2dbc.password=" })
@AutoConfigureWebTestClient
class PlanPageRenderingTest {

	@Autowired
	private WebTestClient webTestClient;

	@Test
	@WithMockUser(roles = "ADMIN")
	void thePlanListRendersWithoutAnyRequestParameter() {
		renderPlans("/plans");
	}

	@Test
	@WithMockUser(roles = "ADMIN")
	void thePlanListRendersTheOutcomeOfAnImport() {
		String body = renderPlans("/plans?imported=3&secrets=2");

		assertThat(body).contains("3 test plan(s) imported.").contains("2 of them had masked credentials");
	}

	@Test
	@WithMockUser(roles = "ADMIN")
	void thePlanListReportsAFailedImport() {
		assertThat(renderPlans("/plans?importError=1")).contains("Import failed");
	}

	@Test
	@WithMockUser(roles = "ADMIN")
	void theImportFormShipsTheScriptThatCarriesTheCsrfTokenInAHeader() {
		String body = renderPlans("/plans");

		// Spring Security never reads the token from a multipart body, so without this
		// the
		// upload is rejected. The layout keeps only <main>, so a script placed outside it
		// is
		// silently dropped. Assert on the script's own identifiers: the token header name
		// also appears in the layout's meta tags, which would mask its absence.
		assertThat(body).as("import form").contains("id=\"planImportForm\"");
		assertThat(body).as("upload script survived the layout").contains("planImportFile");
		assertThat(body).as("script posts to the import endpoint").contains("fetch(form.action");
		assertThat(body).as("token read from the layout meta tags").contains("meta[name=\"_csrf_header\"]");
	}

	@Test
	@WithMockUser(roles = "ADMIN")
	void thePlanListOffersExporting() {
		assertThat(renderPlans("/plans")).contains("/plans/export");
	}

	private String renderPlans(String uri) {
		return this.webTestClient.get()
			.uri(uri)
			.exchange()
			.expectStatus()
			.isOk()
			.expectBody(String.class)
			.returnResult()
			.getResponseBody();
	}

}

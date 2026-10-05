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

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import tools.jackson.databind.ObjectMapper;

import ch.nexsol.orthrusdast.entity.TestPlanEntity;
import ch.nexsol.orthrusdast.model.GatewayExclusions;
import ch.nexsol.orthrusdast.model.ScanConfiguration;
import ch.nexsol.orthrusdast.repository.TestPlanRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.csrf;

/**
 * The gateway exclusions entered in the plan form reach the stored scan configuration
 * (which the workers receive as is), show up again when the plan is edited, and survive
 * an update that does not carry them.
 */
@SpringBootTest(properties = {
		"spring.r2dbc.url=r2dbc:h2:mem:///gatewayexclusionsdb;MODE=PostgreSQL;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE",
		"spring.r2dbc.username=sa", "spring.r2dbc.password=" })
@AutoConfigureWebTestClient
class PlanGatewayExclusionsFormTest {

	@Autowired
	private WebTestClient webTestClient;

	@Autowired
	private TestPlanRepository testPlanRepository;

	private final ObjectMapper objectMapper = new ObjectMapper();

	@Test
	@WithMockUser(roles = "ADMIN")
	void exclusionsAreStoredShownAgainAndKeptWhenNotResubmitted() {
		MultiValueMap<String, String> form = gatewayPlanForm("gw-exclusions");
		form.add("gatewayExcludedRouteIds", "admin-route, metrics\ninternal");
		form.add("gatewayExcludedPaths", "/actuator/**\n\n/admin");
		post("/web/plans", form);

		TestPlanEntity plan = planNamed("gw-exclusions");
		assertThat(exclusionsOf(plan)).isEqualTo(new GatewayExclusions(List.of("admin-route", "metrics", "internal"),
				List.of("/actuator/**", "/admin")));

		String editForm = this.webTestClient.get()
			.uri("/api/plans/{id}/edit", plan.getId())
			.exchange()
			.expectStatus()
			.isOk()
			.expectBody(String.class)
			.returnResult()
			.getResponseBody();
		assertThat(editForm).contains("admin-route, metrics, internal").contains("/actuator/**, /admin");

		MultiValueMap<String, String> update = gatewayPlanForm("gw-exclusions");
		update.add("gatewayExcludedRouteIds", "metrics");
		update.add("gatewayExcludedPaths", "");
		post("/api/plans/" + plan.getId(), update);
		assertThat(exclusionsOf(planNamed("gw-exclusions")))
			.isEqualTo(new GatewayExclusions(List.of("metrics"), List.of()));

		post("/api/plans/" + plan.getId(), gatewayPlanForm("gw-exclusions"));
		assertThat(exclusionsOf(planNamed("gw-exclusions"))).as("an update without the fields keeps them")
			.isEqualTo(new GatewayExclusions(List.of("metrics"), List.of()));
	}

	@Test
	@WithMockUser(roles = "ADMIN")
	void emptyFieldsStoreNoExclusions() {
		MultiValueMap<String, String> form = gatewayPlanForm("gw-no-exclusions");
		form.add("gatewayExcludedRouteIds", " ");
		form.add("gatewayExcludedPaths", "");
		post("/web/plans", form);

		assertThat(exclusionsOf(planNamed("gw-no-exclusions"))).isNull();
	}

	private MultiValueMap<String, String> gatewayPlanForm(String name) {
		MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
		form.add("name", name);
		form.add("target", "http://api-gateway-internal-service:8088");
		form.add("discovererId", "gateway");
		form.add("gatewayType", "spring-cloud-gateway");
		form.add("appUrl", "http://api-gateway-internal-service:8080");
		return form;
	}

	private void post(String uri, MultiValueMap<String, String> form) {
		this.webTestClient.mutateWith(csrf())
			.post()
			.uri(uri)
			.body(BodyInserters.fromFormData(form))
			.exchange()
			.expectStatus()
			.is2xxSuccessful();
	}

	private TestPlanEntity planNamed(String name) {
		return this.testPlanRepository.findAll().filter((plan) -> name.equals(plan.getName())).blockFirst();
	}

	private GatewayExclusions exclusionsOf(TestPlanEntity plan) {
		return this.objectMapper.readValue(plan.getScanConfigurationJson(), ScanConfiguration.class)
			.gatewayExclusions();
	}

}

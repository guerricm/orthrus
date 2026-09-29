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

package ch.nexsol.orthrusai.orchestrator.api;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

import ch.nexsol.orthrus.protocol.ai.PlanRequest;
import ch.nexsol.orthrus.protocol.ai.ScanPlan;
import ch.nexsol.orthrusai.orchestrator.plan.PlanService;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

/**
 * The plan endpoint returns a plan for a valid target and rejects a blank one.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
		properties = { "spring.ai.model.chat=none", "orthrus.ai.enabled=false" })
class PlanControllerTests {

	@LocalServerPort
	private int port;

	@MockitoBean
	private PlanService planService;

	private WebTestClient client;

	@BeforeEach
	void setUp() {
		this.client = WebTestClient.bindToServer().baseUrl("http://localhost:" + this.port).build();
	}

	@Test
	void returnsPlanForValidTarget() {
		ScanPlan plan = new ScanPlan("openapi", List.of("INJECTION"), 10, false, "focus on the API");
		when(this.planService.plan(eq("http://app.test"), any(), any())).thenReturn(Mono.just(plan));

		this.client.post()
			.uri("/api/v1/plan")
			.contentType(MediaType.APPLICATION_JSON)
			.bodyValue(new PlanRequest("http://app.test", "find injection", List.of("openapi")))
			.exchange()
			.expectStatus()
			.isOk()
			.expectBody()
			.jsonPath("$.recommendedDiscoverer")
			.isEqualTo("openapi");
	}

	@Test
	void rejectsBlankTarget() {
		this.client.post()
			.uri("/api/v1/plan")
			.contentType(MediaType.APPLICATION_JSON)
			.bodyValue(new PlanRequest("  ", null, List.of()))
			.exchange()
			.expectStatus()
			.isBadRequest();
	}

}

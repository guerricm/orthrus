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

package ch.nexsol.orthrusai.orchestrator.security;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

import ch.nexsol.orthrus.protocol.ai.PlanRequest;
import ch.nexsol.orthrus.protocol.ai.ScanPlan;
import ch.nexsol.orthrus.protocol.node.NodeClient;
import ch.nexsol.orthrusai.orchestrator.plan.PlanService;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Every API call must carry the shared secret; health stays open for probes.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = { "spring.ai.model.chat=none",
		"orthrus.ai.enabled=false", "orthrus.ai.orchestrator.internal-token=s3cret" })
class InternalTokenWebFilterTests {

	@LocalServerPort
	private int port;

	@MockitoBean
	private PlanService planService;

	private WebTestClient client() {
		return WebTestClient.bindToServer().baseUrl("http://localhost:" + this.port).build();
	}

	@Test
	void anApiCallWithoutTheTokenIsRejected() {
		client().post()
			.uri("/api/v1/recon")
			.contentType(MediaType.APPLICATION_JSON)
			.bodyValue("{\"target\":\"http://app.test\"}")
			.exchange()
			.expectStatus()
			.isUnauthorized();
	}

	@Test
	void anApiCallWithAWrongTokenIsRejected() {
		client().post()
			.uri("/api/v1/plan")
			.header(NodeClient.INTERNAL_TOKEN_HEADER, "guess")
			.contentType(MediaType.APPLICATION_JSON)
			.bodyValue(new PlanRequest("http://app.test", null, List.of()))
			.exchange()
			.expectStatus()
			.isUnauthorized();
	}

	@Test
	void anApiCallWithTheTokenGoesThrough() {
		when(this.planService.plan(any(), any(), any()))
			.thenReturn(Mono.just(new ScanPlan("openapi", List.of(), 10, false, "ok")));

		client().post()
			.uri("/api/v1/plan")
			.header(NodeClient.INTERNAL_TOKEN_HEADER, "s3cret")
			.contentType(MediaType.APPLICATION_JSON)
			.bodyValue(new PlanRequest("http://app.test", null, List.of()))
			.exchange()
			.expectStatus()
			.isOk();
	}

	@Test
	void healthStaysOpenForProbes() {
		client().get().uri("/actuator/health").exchange().expectStatus().isOk();
	}

}

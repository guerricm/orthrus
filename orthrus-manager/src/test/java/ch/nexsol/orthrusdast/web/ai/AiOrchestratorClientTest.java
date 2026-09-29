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

package ch.nexsol.orthrusdast.web.ai;

import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.netty.DisposableServer;
import reactor.netty.http.server.HttpServer;

import ch.nexsol.orthrus.protocol.ai.ScanPlan;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The proxy client asks the orchestrator's plan endpoint and parses the returned plan.
 * Uses an embedded reactor-netty server standing in for the orchestrator.
 */
class AiOrchestratorClientTest {

	private DisposableServer server;

	@AfterEach
	void tearDown() {
		if (this.server != null) {
			this.server.disposeNow();
		}
	}

	@Test
	void suggestsPlanAndParsesResult() {
		String json = "{\"recommendedDiscoverer\":\"openapi\",\"prioritizedFamilies\":[\"INJECTION\",\"XSS\"],"
				+ "\"concurrency\":8,\"includePassed\":false,\"rationale\":\"focus on the API\"}";
		this.server = HttpServer.create()
			.port(0)
			.handle((request, response) -> response.status(200)
				.header("Content-Type", "application/json")
				.sendString(Mono.just(json)))
			.bindNow();

		AiOrchestratorClient client = new AiOrchestratorClient("http://localhost:" + this.server.port(),
				WebClient.builder());

		ScanPlan plan = client.suggestPlan("http://app.test", "find injection", List.of("openapi", "blackbox")).block();

		assertThat(plan).isNotNull();
		assertThat(plan.recommendedDiscoverer()).isEqualTo("openapi");
		assertThat(plan.prioritizedFamilies()).containsExactly("INJECTION", "XSS");
		assertThat(plan.concurrency()).isEqualTo(8);
	}

}

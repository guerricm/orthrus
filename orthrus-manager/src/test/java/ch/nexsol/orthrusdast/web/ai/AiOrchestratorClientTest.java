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

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.netty.DisposableServer;
import reactor.netty.http.server.HttpServer;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The proxy client speaks the orchestrator's campaign contract: it posts a target and
 * parses the campaign result. Uses an embedded reactor-netty server standing in for the
 * orchestrator.
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
	void launchesCampaignAndParsesResult() {
		String json = "{\"plan\":{\"recommendedDiscoverer\":\"openapi\",\"prioritizedFamilies\":[\"INJECTION\"],"
				+ "\"concurrency\":10,\"includePassed\":false,\"rationale\":\"focus on the API\"},"
				+ "\"jobId\":42,\"target\":\"http://app.test\",\"eventStreamUrl\":\"/api/sse/jobs/42/events\"}";
		this.server = HttpServer.create()
			.port(0)
			.handle((request, response) -> response.status(200)
				.header("Content-Type", "application/json")
				.sendString(Mono.just(json)))
			.bindNow();

		AiOrchestratorClient client = new AiOrchestratorClient("http://localhost:" + this.server.port(),
				WebClient.builder());

		CampaignResult result = client.launchCampaign("http://app.test", "find injection").block();

		assertThat(result).isNotNull();
		assertThat(result.jobId()).isEqualTo(42L);
		assertThat(result.plan().recommendedDiscoverer()).isEqualTo("openapi");
		assertThat(result.eventStreamUrl()).isEqualTo("/api/sse/jobs/42/events");
	}

}

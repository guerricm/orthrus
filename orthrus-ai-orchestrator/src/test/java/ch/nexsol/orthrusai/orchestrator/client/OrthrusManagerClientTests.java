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

package ch.nexsol.orthrusai.orchestrator.client;

import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.netty.DisposableServer;
import reactor.netty.http.server.HttpServer;

import ch.nexsol.orthrusai.orchestrator.config.AiOrchestratorProperties;
import ch.nexsol.orthrusai.orchestrator.wire.ScanJobAccepted;
import ch.nexsol.orthrusai.orchestrator.wire.ScanRequest;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The manager client speaks the manager's public JSON contract: it reads discoverers and
 * launches scans. Uses an embedded reactor-netty server standing in for the manager.
 */
class OrthrusManagerClientTests {

	private DisposableServer server;

	@AfterEach
	void tearDown() {
		if (this.server != null) {
			this.server.disposeNow();
		}
	}

	private OrthrusManagerClient clientFor(String jsonBody) {
		this.server = HttpServer.create()
			.port(0)
			.handle((request, response) -> response.status(200)
				.header("Content-Type", "application/json")
				.sendString(Mono.just(jsonBody)))
			.bindNow();
		AiOrchestratorProperties properties = new AiOrchestratorProperties();
		properties.getManager().setUrl("http://localhost:" + this.server.port());
		return new OrthrusManagerClient(properties, WebClient.builder());
	}

	@Test
	void readsDiscoverers() {
		OrthrusManagerClient client = clientFor("[\"openapi\",\"blackbox\"]");

		List<String> discoverers = client.getDiscoverers().block();

		assertThat(discoverers).containsExactly("openapi", "blackbox");
	}

	@Test
	void launchesScanAndParsesAcceptedJob() {
		OrthrusManagerClient client = clientFor(
				"{\"jobId\":42,\"target\":\"http://app.test\",\"status\":\"PENDING\",\"eventStreamUrl\":\"/sse/42\"}");

		ScanRequest request = new ScanRequest("openapi", "http://app.test", List.of(), List.of(), 10, false, "en",
				false);
		ScanJobAccepted accepted = client.launchScan(request).block();

		assertThat(accepted).isNotNull();
		assertThat(accepted.jobId()).isEqualTo(42L);
		assertThat(accepted.eventStreamUrl()).isEqualTo("/sse/42");
	}

}

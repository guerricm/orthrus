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

package ch.nexsol.orthrusai.scanner.client;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import org.awaitility.Awaitility;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.DisposableServer;
import reactor.netty.http.server.HttpServer;

import ch.nexsol.orthrusai.scanner.ai.AgentActivity;
import ch.nexsol.orthrusai.scanner.config.AiScannerProperties;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The AI scanner node registers with the manager and, exactly like a plain worker,
 * re-registers whenever a heartbeat is rejected, so it reappears after the manager
 * restarts or after the node started before the manager was up. Uses an embedded
 * reactor-netty server to avoid an okhttp version clash on the test classpath.
 */
class ManagerClientTests {

	private final List<String> requests = new CopyOnWriteArrayList<>();

	private DisposableServer server;

	private String baseUrl;

	@AfterEach
	void tearDown() {
		if (this.server != null) {
			this.server.disposeNow();
		}
	}

	/**
	 * Serves the manager's internal API, recording each path and answering the heartbeat
	 * with the given status. A 404 mirrors the manager's answer for a node it does not
	 * know.
	 * @param heartbeatStatus the status returned to heartbeats
	 */
	private void startManager(int heartbeatStatus) {
		this.server = HttpServer.create().port(0).handle((request, response) -> {
			this.requests.add(request.uri());
			int status = request.uri().contains("/heartbeat") ? heartbeatStatus : 200;
			return response.status(status).send();
		}).bindNow();
		this.baseUrl = "http://localhost:" + this.server.port();
	}

	private final AgentActivity agentActivity = new AgentActivity();

	private ManagerClient managerClient() {
		AiScannerProperties properties = new AiScannerProperties();
		properties.getMaster().setUrl(this.baseUrl);
		properties.getSlave().setId("ai-scanner-test");
		properties.getSlave().setAdvertisedUrl("http://localhost:8091");
		return new ManagerClient(properties, WebClient.builder(), this.agentActivity);
	}

	@Test
	void aRejectedHeartbeatTriggersReRegistration() {
		startManager(404);
		ManagerClient client = managerClient();

		client.sendHeartbeat();

		Awaitility.await()
			.atMost(Duration.ofSeconds(5))
			.until(() -> this.requests.stream().anyMatch((uri) -> uri.contains("/slaves/register")));
		assertThat(this.requests).anyMatch((uri) -> uri.contains("/heartbeat"));
	}

	@Test
	void anAcceptedHeartbeatDoesNotReRegister() {
		startManager(200);
		ManagerClient client = managerClient();

		client.sendHeartbeat();

		// Give any (unwanted) re-registration time to fire before asserting it did not.
		Awaitility.await()
			.during(Duration.ofSeconds(1))
			.atMost(Duration.ofSeconds(2))
			.until(() -> this.requests.stream().noneMatch((uri) -> uri.contains("/slaves/register")));
	}

	@Test
	void theHeartbeatReportsTheAgentsRunningOnThisNode() {
		startManager(200);
		ManagerClient client = managerClient();
		this.agentActivity.started();
		this.agentActivity.started();

		client.sendHeartbeat();

		Awaitility.await()
			.atMost(Duration.ofSeconds(5))
			.until(() -> this.requests.stream().anyMatch((uri) -> uri.contains("activeAgents=2")));
	}

}

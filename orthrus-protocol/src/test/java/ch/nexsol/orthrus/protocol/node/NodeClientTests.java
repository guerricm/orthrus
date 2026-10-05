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

package ch.nexsol.orthrus.protocol.node;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import org.awaitility.Awaitility;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;
import reactor.netty.DisposableServer;
import reactor.netty.http.server.HttpServer;
import reactor.test.StepVerifier;

import static org.assertj.core.api.Assertions.assertThat;

class NodeClientTests {

	private final List<String> requests = new CopyOnWriteArrayList<>();

	private final List<String> tokens = new CopyOnWriteArrayList<>();

	private DisposableServer server;

	@AfterEach
	void tearDown() {
		if (this.server != null) {
			this.server.disposeNow();
		}
	}

	private NodeClient startManager(int heartbeatStatus, int taskStatus) {
		this.server = HttpServer.create().port(0).handle((request, response) -> {
			this.requests.add(request.uri());
			this.tokens.add(String.valueOf(request.requestHeaders().get(NodeClient.INTERNAL_TOKEN_HEADER)));
			int status = request.uri().contains("/heartbeat") ? heartbeatStatus
					: request.uri().contains("/tasks/") ? taskStatus : 200;
			return response.status(status).send();
		}).bindNow();
		return new NodeClient(WebClient.builder(), "http://localhost:" + this.server.port(), "secret", "node-1",
				"http://node-1:8081", "openapi,sqli,INJECTION");
	}

	@Test
	void everyCallCarriesTheInternalToken() {
		NodeClient client = startManager(200, 200);

		StepVerifier.create(client.failTask(7L, "boom")).verifyComplete();

		assertThat(this.requests).containsExactly("/api/internal/tasks/7/fail");
		assertThat(this.tokens).containsExactly("secret");
	}

	@Test
	void aRejectedHeartbeatTriggersReRegistration() {
		NodeClient client = startManager(404, 200);

		client.heartbeat();

		Awaitility.await()
			.atMost(Duration.ofSeconds(5))
			.until(() -> this.requests.stream().anyMatch((uri) -> uri.contains("/slaves/register")));
		assertThat(this.requests).anyMatch((uri) -> uri.contains("/slaves/node-1/heartbeat?activeTasks=0"));
	}

	@Test
	void anAcceptedHeartbeatDoesNotReRegister() {
		NodeClient client = startManager(200, 200);

		client.reportLoad(3);

		Awaitility.await()
			.during(Duration.ofSeconds(1))
			.atMost(Duration.ofSeconds(2))
			.until(() -> this.requests.stream().noneMatch((uri) -> uri.contains("/slaves/register")));
		assertThat(this.requests).anyMatch((uri) -> uri.contains("activeTasks=3"));
	}

	@Test
	void theHeartbeatCarriesTheActiveAgentCountReadAtSendTime() {
		this.server = HttpServer.create().port(0).handle((request, response) -> {
			this.requests.add(request.uri());
			return response.status(200).send();
		}).bindNow();
		AtomicInteger agents = new AtomicInteger(12);
		NodeClient client = new NodeClient(WebClient.builder(), "http://localhost:" + this.server.port(), "secret",
				"node-1", "http://node-1:8081", "AI-EXECUTOR,INJECTION", agents::get);

		client.reportLoad(4);
		agents.set(3);
		client.heartbeat();

		Awaitility.await().atMost(Duration.ofSeconds(5)).until(() -> this.requests.size() == 2);
		assertThat(this.requests).anyMatch((uri) -> uri.contains("activeTasks=4&activeAgents=12"))
			.anyMatch((uri) -> uri.contains("activeTasks=4&activeAgents=3"));
	}

	@Test
	void aWorkerReportsNoActiveAgents() {
		NodeClient client = startManager(200, 200);

		client.heartbeat();

		Awaitility.await().atMost(Duration.ofSeconds(5)).until(() -> !this.requests.isEmpty());
		assertThat(this.requests).anyMatch((uri) -> uri.contains("activeAgents=0"));
	}

	@Test
	void reportingErrorsPropagateToTheCaller() {
		NodeClient client = startManager(200, 500);

		StepVerifier.create(client.completeTask(7L, Instant.now(), 1, 0))
			.expectError(WebClientResponseException.class)
			.verify();
		StepVerifier.create(client.sendTaskAttemptsBatch(7L, List.of()))
			.expectError(WebClientResponseException.class)
			.verify();
	}

	@Test
	void markOfflineNeverFails() {
		NodeClient client = startManager(200, 500);
		this.server.disposeNow();

		client.markOffline();

		assertThat(Mono.empty().blockOptional()).isEmpty();
	}

}

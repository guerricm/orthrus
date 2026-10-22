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

package ch.nexsol.orthrusai.scanner.ai;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.DisposableServer;
import reactor.netty.http.server.HttpServer;
import reactor.test.StepVerifier;
import tools.jackson.databind.ObjectMapper;

import ch.nexsol.orthrus.protocol.ai.Credential;
import ch.nexsol.orthrus.protocol.ai.Endpoint;
import ch.nexsol.orthrusai.scanner.config.AiScannerProperties;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * The baseline request tells the executor whether the endpoint accepts the configured
 * identity before any agent spends its budget on it. Uses an embedded reactor-netty
 * server.
 */
class FamilyAgentBaselineTests {

	private final FamilyAgent agent = new FamilyAgent(mock(ChatClient.class), WebClient.builder(), new ScopeGuard(),
			new ObjectMapper(), new AiScannerProperties(), new AgentActivity());

	private final AtomicReference<String> seenUri = new AtomicReference<>();

	private final AtomicReference<String> seenAuthorization = new AtomicReference<>();

	private DisposableServer server;

	@BeforeEach
	void setUp() {
		this.server = HttpServer.create().port(0).handle((request, response) -> {
			this.seenUri.set(request.uri());
			this.seenAuthorization.set(request.requestHeaders().get("Authorization"));
			return response.status(403).send();
		}).bindNow();
	}

	@AfterEach
	void tearDown() {
		this.server.disposeNow();
	}

	@Test
	void reportsTheStatusOfTheRequestSentWithTheCredentials() {
		Endpoint endpoint = new Endpoint("DELETE", "http://localhost:" + this.server.port() + "/rooms/{roomId}");
		ProbeConfig config = new ProbeConfig(List.of(new Credential("HEADER", "Authorization", "Bearer t")), false,
				5000);

		StepVerifier.create(this.agent.baselineStatus(endpoint, config)).expectNext(403).verifyComplete();
		assertThat(this.seenUri.get()).isEqualTo("/rooms/1");
		assertThat(this.seenAuthorization.get()).isEqualTo("Bearer t");
	}

	@Test
	void anUnreachableEndpointGivesNoStatus() {
		int port = this.server.port();
		this.server.disposeNow();
		Endpoint endpoint = new Endpoint("GET", "http://localhost:" + port + "/rooms");

		StepVerifier.create(this.agent.baselineStatus(endpoint, ProbeConfig.defaults()))
			.expectComplete()
			.verify(Duration.ofSeconds(15));
	}

}

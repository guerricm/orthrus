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

import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationHandler;
import io.micrometer.observation.ObservationRegistry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.netty.DisposableServer;
import reactor.netty.http.server.HttpServer;
import tools.jackson.databind.ObjectMapper;

import ch.nexsol.orthrus.protocol.ai.Endpoint;
import ch.nexsol.orthrusai.scanner.ai.tool.HttpProbeTool;
import ch.nexsol.orthrusai.scanner.config.AiScannerProperties;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Every probe an agent forges has its own URL, so observing probes would mint one metric
 * tag per payload until Micrometer's cap is hit. The probe client must stay out of the
 * application's HTTP client metrics.
 */
class FamilyAgentProbeMetricsTests {

	private DisposableServer server;

	@AfterEach
	void tearDown() {
		if (this.server != null) {
			this.server.disposeNow();
		}
	}

	@Test
	void probesAreNotRecordedAsHttpClientObservations() {
		this.server = HttpServer.create()
			.port(0)
			.handle((request, response) -> response.status(200).sendString(Mono.just("ok")))
			.bindNow();
		String target = "http://localhost:" + this.server.port() + "/api/pet/{petId}";

		AtomicInteger observations = new AtomicInteger();
		ObservationRegistry registry = ObservationRegistry.create();
		registry.observationConfig().observationHandler(new ObservationHandler<>() {

			@Override
			public void onStart(Observation.Context context) {
				observations.incrementAndGet();
			}

			@Override
			public boolean supportsContext(Observation.Context context) {
				return true;
			}

		});

		AtomicReference<String> probeResult = new AtomicReference<>();
		ChatClient chatClient = mock(ChatClient.class, RETURNS_DEEP_STUBS);
		ChatClient.ChatClientRequestSpec afterTools = mock(ChatClient.ChatClientRequestSpec.class, RETURNS_DEEP_STUBS);
		when(chatClient.prompt().system(anyString()).user(anyString()).tools(any(), any())).thenAnswer((invocation) -> {
			HttpProbeTool probe = invocation.getArgument(0);
			when(afterTools.call().content()).thenAnswer((call) -> {
				probeResult.set(probe.sendRequest(target.replace("{petId}", "42"), "GET", null, null));
				return "done";
			});
			return afterTools;
		});

		FamilyAgent agent = new FamilyAgent(chatClient, WebClient.builder().observationRegistry(registry),
				new ScopeGuard(), new ObjectMapper(), new AiScannerProperties(), new AgentActivity());

		agent.scan("INJECTION", new Endpoint("GET", target), null, ProbeConfig.defaults());

		assertThat(probeResult.get()).as("the probe reached the target").startsWith("HTTP 200");
		assertThat(observations).as("no HTTP client observation for agent probes").hasValue(0);
	}

}

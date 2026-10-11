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

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.ollama.OllamaChatModel;
import org.springframework.ai.ollama.api.OllamaApi;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.netty.DisposableServer;
import reactor.netty.http.server.HttpServer;
import tools.jackson.databind.ObjectMapper;

import ch.nexsol.orthrus.protocol.ai.Endpoint;
import ch.nexsol.orthrusai.scanner.config.AiScannerProperties;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Each tool call costs one LLM round trip, so the agent loop is bounded by
 * {@code max-tool-iterations}, the model's hidden reasoning is off for Ollama, and the
 * responses fed back to the model are truncated. Runs the real Ollama client and tool
 * loop against a fake Ollama that asks for a probe on every turn.
 */
class AgentLoopLimitsTests {

	private static final int MAX_TOOL_CALLS = 3;

	private static final int MAX_RESPONSE_CHARS = 200;

	private final List<String> chatRequests = new CopyOnWriteArrayList<>();

	private final AtomicInteger probes = new AtomicInteger();

	private DisposableServer server;

	private String target;

	@BeforeEach
	void startFakeOllamaAndTarget() {
		this.server = HttpServer.create().port(0).route((routes) -> routes.post("/api/chat", (request, response) -> {
			return request.receive().aggregate().asString().flatMap((body) -> {
				this.chatRequests.add(body);
				return Mono.just(body);
			})
				.flatMap((body) -> response.header("Content-Type", "application/json")
					.sendString(Mono.just(toolCallAskingFor(this.target)))
					.then());
		}).get("/target", (request, response) -> {
			this.probes.incrementAndGet();
			return response.sendString(Mono.just("x".repeat(5000)));
		})).bindNow();
		this.target = "http://localhost:" + this.server.port() + "/target";
	}

	@AfterEach
	void stop() {
		this.server.disposeNow();
	}

	@Test
	@Timeout(30)
	void theLoopStopsAtTheToolCallLimitWithoutThinkingAndWithTruncatedResponses() {
		AiScannerProperties properties = new AiScannerProperties();
		properties.getAi().getScanner().setModel("qwen-test");
		properties.getAi().getBudget().setMaxToolIterations(MAX_TOOL_CALLS);
		properties.getAi().getBudget().setMaxResponseChars(MAX_RESPONSE_CHARS);
		OllamaChatModel ollama = OllamaChatModel.builder()
			.ollamaApi(OllamaApi.builder().baseUrl("http://localhost:" + this.server.port()).build())
			.build();
		ChatClient chatClient = new ChatClientConfig().scannerChatClient(ollama, properties);
		AgentActivity activity = new AgentActivity();
		FamilyAgent agent = new FamilyAgent(chatClient, WebClient.builder(), new ScopeGuard(), new ObjectMapper(),
				properties, activity);

		agent.scan("INJECTION", new Endpoint("GET", this.target), null, ProbeConfig.defaults());

		assertThat(this.probes).as("one probe per allowed tool call").hasValue(MAX_TOOL_CALLS);
		assertThat(this.chatRequests).as("one LLM round trip per tool call, plus the one that hit the limit")
			.hasSize(MAX_TOOL_CALLS + 1);
		assertThat(this.chatRequests).as("the model's hidden reasoning is turned off")
			.allMatch((body) -> body.contains("\"think\":false"));
		assertThat(this.chatRequests.get(1)).as("probe responses are truncated before reaching the model")
			.contains("[truncated]")
			.doesNotContain("x".repeat(MAX_RESPONSE_CHARS + 1));
		assertThat(this.chatRequests.get(MAX_TOOL_CALLS)).as("the last allowed call tells the model to wrap up")
			.contains("LAST_REQUEST");
		assertThat(activity.active()).isZero();
	}

	private static String toolCallAskingFor(String url) {
		return "{\"model\":\"qwen-test\",\"created_at\":\"2026-10-05T00:00:00Z\",\"message\":{\"role\":\"assistant\","
				+ "\"content\":\"\",\"tool_calls\":[{\"function\":{\"name\":\"sendRequest\",\"arguments\":"
				+ "{\"url\":\"" + url + "\",\"method\":\"GET\"}}}]},\"done\":true,\"done_reason\":\"stop\"}";
	}

}

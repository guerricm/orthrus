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

package ch.nexsol.orthrusai.scanner.ai.tool;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.netty.DisposableServer;
import reactor.netty.http.server.HttpServer;
import tools.jackson.databind.ObjectMapper;

import ch.nexsol.orthrusai.scanner.ai.RunContext;
import ch.nexsol.orthrusai.scanner.ai.ScopeGuard;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The HTTP tool must actually reach the in-scope target, refuse out-of-scope hosts
 * without spending budget, and stop once the budget is exhausted. Uses an embedded
 * reactor-netty server to avoid an okhttp version clash with the LLM provider on the
 * classpath.
 */
class HttpProbeToolTests {

	private DisposableServer server;

	private String target;

	private final ScopeGuard scopeGuard = new ScopeGuard();

	private final ObjectMapper objectMapper = new ObjectMapper();

	private final WebClient webClient = WebClient.builder().build();

	@BeforeEach
	void setUp() {
		this.server = HttpServer.create()
			.port(0)
			.handle((request, response) -> response.status(200).sendString(Mono.just("{\"ok\":true}")))
			.bindNow();
		this.target = "http://localhost:" + this.server.port() + "/api";
	}

	@AfterEach
	void tearDown() {
		this.server.disposeNow();
	}

	@Test
	void probesInScopeTargetAndConsumesBudget() {
		RunContext ctx = new RunContext(this.target, "ai-injection", 5);
		HttpProbeTool tool = new HttpProbeTool(this.webClient, this.scopeGuard, this.objectMapper, ctx);

		String result = tool.sendRequest(this.target, "GET", null, null);

		assertThat(result).contains("HTTP 200");
		assertThat(result).contains("{\"ok\":true}");
		assertThat(ctx.httpCallsUsed()).isEqualTo(1);
	}

	@Test
	void refusesOutOfScopeWithoutConsumingBudget() {
		RunContext ctx = new RunContext(this.target, "ai-injection", 5);
		HttpProbeTool tool = new HttpProbeTool(this.webClient, this.scopeGuard, this.objectMapper, ctx);

		String result = tool.sendRequest("http://evil.test/steal", "GET", null, null);

		assertThat(result).startsWith("REFUSED");
		assertThat(ctx.httpCallsUsed()).isZero();
	}

	@Test
	void stopsWhenBudgetExhausted() {
		RunContext ctx = new RunContext(this.target, "ai-injection", 1);
		HttpProbeTool tool = new HttpProbeTool(this.webClient, this.scopeGuard, this.objectMapper, ctx);

		tool.sendRequest(this.target, "GET", null, null);
		String second = tool.sendRequest(this.target, "GET", null, null);

		assertThat(second).startsWith("BUDGET_EXCEEDED");
	}

}

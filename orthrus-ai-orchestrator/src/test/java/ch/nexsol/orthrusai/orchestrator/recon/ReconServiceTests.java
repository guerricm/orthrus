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

package ch.nexsol.orthrusai.orchestrator.recon;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.netty.DisposableServer;
import reactor.netty.http.server.HttpServer;
import tools.jackson.databind.ObjectMapper;

import ch.nexsol.orthrusai.orchestrator.model.ReconResult;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The orchestrator's recon maps OpenAPI endpoints against the correct server base path
 * and fingerprints the target. Uses an embedded reactor-netty server to avoid an okhttp
 * version clash on the test classpath.
 */
class ReconServiceTests {

	private final ReconService reconService = new ReconService(WebClient.builder(), new ObjectMapper());

	private DisposableServer server;

	@AfterEach
	void tearDown() {
		if (this.server != null) {
			this.server.disposeNow();
		}
	}

	private String serve(String contentType, String body) {
		this.server = HttpServer.create()
			.port(0)
			.handle((request, response) -> response.status(200)
				.header("Content-Type", contentType)
				.header("Server", "test-server")
				.sendString(Mono.just(body)))
			.bindNow();
		return "http://localhost:" + this.server.port();
	}

	@Test
	void mapsEndpointsAgainstTheRelativeServerBasePath() {
		String spec = """
				{"openapi":"3.0.0","servers":[{"url":"/api/v3"}],"paths":{"/pet":{"get":{},"post":{}}}}""";
		String host = serve("application/json", spec);
		String target = host + "/api/v3/openapi.json";

		ReconResult result = this.reconService.discover(target).block();

		assertThat(result.baseUrl()).isEqualTo(host + "/api/v3");
		assertThat(result.endpoints()).hasSize(2);
		assertThat(result.endpoints()).allMatch((e) -> e.url().equals(host + "/api/v3/pet"));
		assertThat(result.context()).contains("test-server");
	}

	@Test
	void fallsBackToTheTargetWhenNotOpenApi() {
		String target = serve("text/html", "<html>hello</html>") + "/";

		ReconResult result = this.reconService.discover(target).block();

		assertThat(result.endpoints()).hasSize(1);
		assertThat(result.endpoints().get(0).method()).isEqualTo("GET");
		assertThat(result.endpoints().get(0).url()).isEqualTo(target);
	}

}

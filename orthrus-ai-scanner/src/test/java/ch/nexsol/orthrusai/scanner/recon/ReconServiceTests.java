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

package ch.nexsol.orthrusai.scanner.recon;

import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.netty.DisposableServer;
import reactor.netty.http.server.HttpServer;
import tools.jackson.databind.ObjectMapper;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Recon turns an OpenAPI document into per-method endpoints and otherwise falls back to
 * the target. Uses an embedded reactor-netty server to avoid an okhttp version clash on
 * the test classpath.
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
			.handle((request,
					response) -> response.status(200).header("Content-Type", contentType).sendString(Mono.just(body)))
			.bindNow();
		return "http://localhost:" + this.server.port();
	}

	@Test
	void parsesOpenApiPathsAndMethods() {
		String spec = """
				{"openapi":"3.0.0","paths":{"/users":{"get":{},"post":{}},"/users/{id}":{"delete":{}}}}""";
		String target = serve("application/json", spec) + "/openapi.json";

		List<DiscoveredEndpoint> endpoints = this.reconService.discover(target).block();

		assertThat(endpoints).hasSize(3);
		assertThat(endpoints).anyMatch((e) -> e.method().equals("GET") && e.url().endsWith("/users"));
		assertThat(endpoints).anyMatch((e) -> e.method().equals("POST") && e.url().endsWith("/users"));
		assertThat(endpoints).anyMatch((e) -> e.method().equals("DELETE") && e.url().endsWith("/users/{id}"));
	}

	@Test
	void fallsBackToTargetWhenNotOpenApi() {
		String target = serve("text/html", "<html>hello</html>") + "/";

		List<DiscoveredEndpoint> endpoints = this.reconService.discover(target).block();

		assertThat(endpoints).hasSize(1);
		assertThat(endpoints.get(0).method()).isEqualTo("GET");
	}

}

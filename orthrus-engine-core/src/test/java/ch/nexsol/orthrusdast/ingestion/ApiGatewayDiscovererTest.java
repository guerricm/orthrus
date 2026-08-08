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

package ch.nexsol.orthrusdast.ingestion;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import ch.nexsol.orthrusdast.config.OrthrusProperties;
import ch.nexsol.orthrusdast.model.GatewayType;
import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.ScanConfiguration;

import static org.assertj.core.api.Assertions.assertThat;

class ApiGatewayDiscovererTest {

	private MockWebServer mockWebServer;

	private ApiGatewayDiscoverer discoverer;

	@BeforeEach
	void setUp() throws IOException {
		mockWebServer = new MockWebServer();
		mockWebServer.start();
		BlackboxDiscoverer mockBlackbox = new BlackboxDiscoverer(new OrthrusProperties()) {
			@Override
			public Mono<List<Operation>> discover(String target, ScanConfiguration config) {
				Operation op = new Operation(target, HttpMethod.GET, Map.of(), Map.of(), null, List.of(), List.of(),
						null);
				return Mono.just(List.of(op));
			}
		};
		discoverer = new ApiGatewayDiscoverer(mockBlackbox);
	}

	@AfterEach
	void tearDown() throws IOException {
		mockWebServer.shutdown();
	}

	@Test
	void testDiscover_KongGateway() {
		String url = mockWebServer.url("/").toString();

		mockWebServer.setDispatcher(new Dispatcher() {
			@Override
			public MockResponse dispatch(RecordedRequest request) {
				if (request.getPath().equals("/routes")) {
					return new MockResponse().setResponseCode(200)
						.setHeader("Content-Type", "application/json")
						.setBody("{\"data\": [{\"paths\": [\"/api/v1/users\"], \"methods\": [\"GET\", \"POST\"]}]}");
				}
				return new MockResponse().setResponseCode(404);
			}
		});

		ScanConfiguration config = new ScanConfiguration(List.of(), List.of(), 10, 5000, 10000, false, "json", null,
				null, "en", false, GatewayType.KONG, null, null, null, null);

		StepVerifier.create(discoverer.discover(url, config)).assertNext((operations) -> {
			assertThat(operations).hasSize(1);
			assertThat(operations.stream().anyMatch((o) -> o.url().endsWith("/api/v1/users"))).isTrue();
		}).verifyComplete();
	}

	@Test
	void testDiscover_TraefikGateway() {
		String url = mockWebServer.url("/").toString();

		mockWebServer.setDispatcher(new Dispatcher() {
			@Override
			public MockResponse dispatch(RecordedRequest request) {
				if (request.getPath().equals("/api/http/routers")) {
					return new MockResponse().setResponseCode(200)
						.setHeader("Content-Type", "application/json")
						.setBody("[{\"rule\": \"PathPrefix(`/api/v2/orders`)\"}]");
				}
				return new MockResponse().setResponseCode(404);
			}
		});

		ScanConfiguration config = new ScanConfiguration(List.of(), List.of(), 10, 5000, 10000, false, "json", null,
				null, "en", false, GatewayType.TRAEFIK, "api.traefik.internal", null, null, null);

		StepVerifier.create(discoverer.discover(url, config)).assertNext((operations) -> {
			assertThat(operations).isNotEmpty();
			assertThat(operations).hasSize(1);
			Operation op = operations.get(0);
			assertThat(op.url().endsWith("/api/v2/orders")).isTrue();
			// Traefik adds default methods if not specified
			assertThat(op.method()).isEqualTo(HttpMethod.GET);
		}).verifyComplete();
	}

	@Test
	void testDiscover_KubernetesIngress_WithToken() {
		String url = mockWebServer.url("/").toString();

		mockWebServer.setDispatcher(new Dispatcher() {
			@Override
			public MockResponse dispatch(RecordedRequest request) {
				if (!"Bearer test-k8s-token".equals(request.getHeader("Authorization"))) {
					return new MockResponse().setResponseCode(401);
				}
				if (request.getPath().equals("/apis/networking.k8s.io/v1/ingresses")) {
					return new MockResponse().setResponseCode(200)
						.setHeader("Content-Type", "application/json")
						.setBody(
								"{\"items\": [{\"spec\": {\"rules\": [{\"host\": \"example.com\", \"http\": {\"paths\": [{\"path\": \"/login\"}]}}]}}]}");
				}
				return new MockResponse().setResponseCode(404);
			}
		});

		ScanConfiguration config = new ScanConfiguration(List.of(), List.of(), 10, 5000, 10000, false, "json", null,
				null, "en", false, GatewayType.K8S, null, "test-k8s-token", null, null);

		StepVerifier.create(discoverer.discover(url, config)).assertNext((operations) -> {
			assertThat(operations).hasSize(1);
			assertThat(operations.get(0).url().endsWith("/login")).isTrue();
		}).verifyComplete();
	}

}

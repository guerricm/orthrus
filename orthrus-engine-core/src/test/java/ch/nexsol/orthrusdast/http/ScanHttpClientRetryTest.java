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

package ch.nexsol.orthrusdast.http;

import java.io.IOException;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.web.reactive.function.client.WebClient;

import ch.nexsol.orthrusdast.config.OrthrusProperties;
import ch.nexsol.orthrusdast.model.Operation;

import static org.assertj.core.api.Assertions.assertThat;

class ScanHttpClientRetryTest {

	private MockWebServer server;

	private ScanHttpClient client;

	@BeforeEach
	void setUp() throws IOException {
		server = new MockWebServer();
		server.start();

		OrthrusProperties props = new OrthrusProperties();
		props.getHttp().setRetryBackoffMs(1);
		props.getHttp().setRetryMaxBackoffMs(2);
		props.getHttp().setMaxRetries(4);
		client = new ScanHttpClient(WebClient.create(), props);
	}

	@AfterEach
	void tearDown() throws IOException {
		server.shutdown();
	}

	@Test
	void retriesTransientStatusThenSucceeds() {
		server.enqueue(new MockResponse().setResponseCode(503).setBody("try later"));
		server.enqueue(new MockResponse().setResponseCode(503).setBody("try later"));
		server.enqueue(new MockResponse().setResponseCode(200).setBody("ok"));

		Operation op = Operation.simple(server.url("/").toString(), HttpMethod.GET);
		ScanHttpResponse response = client.send(op).block();

		assertThat(response).isNotNull();
		assertThat(response.statusCode().value()).isEqualTo(200);
		assertThat(response.body()).isEqualTo("ok");
		assertThat(server.getRequestCount()).isEqualTo(3);
	}

	@Test
	void surfacesRealResponseWhenRetriesExhausted() {
		for (int i = 0; i < 6; i++) {
			server.enqueue(new MockResponse().setResponseCode(429).setBody("rate limited"));
		}

		Operation op = Operation.simple(server.url("/").toString(), HttpMethod.GET);
		ScanHttpResponse response = client.send(op).block();

		// After exhausting retries the actual 429 (with its body) is returned, not a
		// synthetic 503 error, so scanners judge the real status.
		assertThat(response).isNotNull();
		assertThat(response.statusCode().value()).isEqualTo(429);
		assertThat(response.body()).isEqualTo("rate limited");
		// Initial attempt + 4 retries.
		assertThat(server.getRequestCount()).isEqualTo(5);
	}

	@Test
	void blockingStatusUsesSmallerBudget() {
		// 403 is retried only blockingMaxRetries (default 1) times, so 2 requests total,
		// then the real 403 is surfaced — it does not pay the full transient budget.
		for (int i = 0; i < 6; i++) {
			server.enqueue(new MockResponse().setResponseCode(403).setBody("blocked"));
		}

		Operation op = Operation.simple(server.url("/").toString(), HttpMethod.GET);
		ScanHttpResponse response = client.send(op).block();

		assertThat(response).isNotNull();
		assertThat(response.statusCode().value()).isEqualTo(403);
		assertThat(response.body()).isEqualTo("blocked");
		assertThat(server.getRequestCount()).isEqualTo(2);
	}

	@Test
	void serverErrorUsesSmallerBudget() {
		// 500 (typically an error-based injection signal) is retried only once.
		for (int i = 0; i < 6; i++) {
			server.enqueue(new MockResponse().setResponseCode(500).setBody("boom"));
		}

		Operation op = Operation.simple(server.url("/").toString(), HttpMethod.GET);
		ScanHttpResponse response = client.send(op).block();

		assertThat(response).isNotNull();
		assertThat(response.statusCode().value()).isEqualTo(500);
		assertThat(server.getRequestCount()).isEqualTo(2);
	}

	@Test
	void doesNotRetryFinalStatus() {
		server.enqueue(new MockResponse().setResponseCode(404).setBody("nope"));

		Operation op = Operation.simple(server.url("/").toString(), HttpMethod.GET);
		ScanHttpResponse response = client.send(op).block();

		assertThat(response).isNotNull();
		assertThat(response.statusCode().value()).isEqualTo(404);
		assertThat(server.getRequestCount()).isEqualTo(1);
	}

	@Test
	void canDisableRetryPerRequest() {
		server.enqueue(new MockResponse().setResponseCode(503).setBody("down"));

		Operation op = Operation.simple(server.url("/").toString(), HttpMethod.GET);
		ScanHttpResponse response = client.send(op, false).block();

		assertThat(response).isNotNull();
		assertThat(response.statusCode().value()).isEqualTo(503);
		assertThat(server.getRequestCount()).isEqualTo(1);
	}

}

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

package ch.nexsol.orthrusdast.scanner;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.web.reactive.function.client.WebClient;

import ch.nexsol.orthrus.protocol.node.Vulnerability;
import ch.nexsol.orthrusdast.config.OrthrusProperties;
import ch.nexsol.orthrusdast.http.ScanHttpClient;
import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.SecurityScheme;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A cross-site request only carries what the browser attaches on its own: cookies. An API
 * authenticated by a header (API key, bearer token), or not authenticated at all, offers
 * nothing to forge, so accepting a cross-origin request there is not CSRF.
 */
class CsrfScannerTest {

	private MockWebServer server;

	private CsrfScanner scanner;

	@BeforeEach
	void setUp() throws IOException {
		this.server = new MockWebServer();
		this.server.start();
		OrthrusProperties properties = new OrthrusProperties();
		properties.getHttp().setRetryBackoffMs(1);
		properties.getHttp().setRetryMaxBackoffMs(2);
		this.scanner = new CsrfScanner(new ScanHttpClient(WebClient.create(), properties));
	}

	@AfterEach
	void tearDown() throws IOException {
		this.server.shutdown();
	}

	@Test
	void aHeaderAuthenticatedApiIsNotReported() {
		acceptEverything(new MockResponse().setBody("deleted"));
		Operation delete = operation(Map.of(), SecurityScheme.apiKey("k", "api_key"));

		assertThat(scan(delete)).isEmpty();
	}

	@Test
	void anUnauthenticatedApiIsNotReported() {
		acceptEverything(new MockResponse().setBody("deleted"));

		assertThat(scan(operation(Map.of(), null))).isEmpty();
	}

	@Test
	void aCookieAuthenticatedRequestIsReported() {
		acceptEverything(new MockResponse().setBody("deleted"));
		Operation delete = operation(Map.of("Cookie", "SESSION=abc"), null);

		assertThat(scan(delete)).extracting(Vulnerability::name)
			.contains("Cross-Site Request Forgery (CSRF) - Missing Token");
	}

	@Test
	void aCookieSetByTheTargetOnAHeaderAuthenticatedRequestIsNotReported() {
		acceptEverything(new MockResponse().setBody("deleted").addHeader("Set-Cookie", "JSESSIONID=abc; Path=/"));
		Operation delete = operation(Map.of(), SecurityScheme.apiKey("k", "api_key"));

		assertThat(scan(delete)).isEmpty();
	}

	private void acceptEverything(MockResponse response) {
		for (int i = 0; i < 10; i++) {
			this.server.enqueue(response);
		}
	}

	private Operation operation(Map<String, String> headers, SecurityScheme auth) {
		return new Operation(this.server.url("/api/pet/1").toString(), HttpMethod.DELETE, headers, Map.of(), null,
				List.of(), List.of(), auth);
	}

	private List<Vulnerability> scan(Operation operation) {
		return this.scanner.scan(operation).collectList().block();
	}

}

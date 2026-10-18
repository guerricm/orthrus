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

import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.web.reactive.function.client.WebClient;

import ch.nexsol.orthrus.protocol.node.Vulnerability;
import ch.nexsol.orthrusdast.config.OrthrusProperties;
import ch.nexsol.orthrusdast.http.ScanHttpClient;
import ch.nexsol.orthrusdast.model.Operation;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A server error only points at parameter pollution when the same request without the
 * duplicate succeeds; an endpoint that already fails on the unpolluted request says
 * nothing about duplicates.
 */
class HppScannerTest {

	private MockWebServer server;

	private HppScanner scanner;

	@BeforeEach
	void setUp() throws IOException {
		this.server = new MockWebServer();
		this.server.start();
		OrthrusProperties properties = new OrthrusProperties();
		properties.getHttp().setRetryBackoffMs(1);
		properties.getHttp().setRetryMaxBackoffMs(2);
		properties.getHttp().setMaxRetries(0);
		this.scanner = new HppScanner(new ScanHttpClient(WebClient.create(), properties));
	}

	@AfterEach
	void tearDown() throws IOException {
		this.server.shutdown();
	}

	@Test
	void anEndpointFailingEvenWithoutTheDuplicateIsNotReported() {
		respond((body) -> 500);

		assertThat(scan()).isEmpty();
	}

	@Test
	void anEndpointFailingOnlyOnTheDuplicateIsReported() {
		respond((body) -> body.contains("orthrus_hpp_test") ? 500 : 200);

		assertThat(scan()).extracting(Vulnerability::name).contains("HTTP Parameter Pollution (HPP) - Server Error");
	}

	private void respond(StatusForBody statusForBody) {
		this.server.setDispatcher(new Dispatcher() {
			@Override
			public MockResponse dispatch(RecordedRequest request) {
				return new MockResponse().setResponseCode(statusForBody.status(request.getBody().readUtf8()));
			}
		});
	}

	private List<Vulnerability> scan() {
		Operation post = new Operation(this.server.url("/api/pet").toString(), HttpMethod.POST,
				Map.of("Content-Type", "application/json"), Map.of(), "{\"name\":\"doggie\"}", List.of(),
				List.of("application/json"), null);
		return this.scanner.scan(post).collectList().block();
	}

	private interface StatusForBody {

		int status(String body);

	}

}

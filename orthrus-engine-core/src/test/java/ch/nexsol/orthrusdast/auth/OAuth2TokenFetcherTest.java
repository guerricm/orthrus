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

package ch.nexsol.orthrusdast.auth;

import java.io.IOException;
import java.util.List;

import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import reactor.test.StepVerifier;

import ch.nexsol.orthrusdast.model.OAuth2Config;

import static org.assertj.core.api.Assertions.assertThat;

class OAuth2TokenFetcherTest {

	private MockWebServer mockWebServer;

	private OAuth2TokenFetcher fetcher;

	private String tokenUrl;

	@BeforeEach
	void setUp() throws IOException {
		mockWebServer = new MockWebServer();
		mockWebServer.start();
		tokenUrl = mockWebServer.url("/token").toString();
		fetcher = new OAuth2TokenFetcher();
	}

	@AfterEach
	void tearDown() throws IOException {
		mockWebServer.shutdown();
	}

	@Test
	void testFetchTokens_Success() {
		mockWebServer.setDispatcher(new Dispatcher() {
			@Override
			public MockResponse dispatch(RecordedRequest request) {
				String body = request.getBody().readUtf8();
				if (body.contains("username=admin")) {
					return new MockResponse().setResponseCode(200)
						.setHeader("Content-Type", "application/json")
						.setBody("{\"access_token\": \"PRIMARY_TOKEN\", \"token_type\": \"Bearer\"}");
				}
				else if (body.contains("username=user")) {
					return new MockResponse().setResponseCode(200)
						.setHeader("Content-Type", "application/json")
						.setBody("{\"access_token\": \"SECONDARY_TOKEN\", \"token_type\": \"Bearer\"}");
				}
				return new MockResponse().setResponseCode(400);
			}
		});

		OAuth2Config config = new OAuth2Config(tokenUrl, "test-client", "test-secret", "password",
				List.of("admin:pass", "user:pass"));

		StepVerifier.create(fetcher.fetchTokens(config)).assertNext((tokens) -> {
			assertThat(tokens).hasSize(2);
			assertThat(tokens.get(0).value()).isEqualTo("PRIMARY_TOKEN");
			assertThat(tokens.get(1).value()).isEqualTo("SECONDARY_TOKEN");
		}).verifyComplete();
	}

	@Test
	void testFetchTokens_EmptyCredentials() {
		OAuth2Config config = new OAuth2Config(tokenUrl, "test-client", "test-secret", "password", List.of());

		StepVerifier.create(fetcher.fetchTokens(config))
			.assertNext((tokens) -> assertThat(tokens).isEmpty())
			.verifyComplete();
	}

}

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

import ch.nexsol.orthrusdast.model.GatewayType;
import ch.nexsol.orthrusdast.model.OAuth2Config;
import ch.nexsol.orthrusdast.model.ScanConfiguration;
import ch.nexsol.orthrusdast.model.SecurityScheme;

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
				List.of("admin:pass", "user:pass"), null);

		StepVerifier.create(fetcher.fetchTokens(config)).assertNext((tokens) -> {
			assertThat(tokens).hasSize(2);
			assertThat(tokens.get(0).value()).isEqualTo("PRIMARY_TOKEN");
			assertThat(tokens.get(1).value()).isEqualTo("SECONDARY_TOKEN");
		}).verifyComplete();
	}

	@Test
	void refreshAuthReplacesTheStoredTokenWithAFreshOne() {
		mockWebServer.enqueue(new MockResponse().setResponseCode(200)
			.setHeader("Content-Type", "application/json")
			.setBody("{\"access_token\": \"FRESH_TOKEN\", \"token_type\": \"Bearer\"}"));
		SecurityScheme secondary = SecurityScheme.bearer("SECONDARY");
		ScanConfiguration config = config(clientCredentials(), SecurityScheme.bearer("EXPIRED"), secondary);

		StepVerifier.create(fetcher.refreshAuth(config)).assertNext((refreshed) -> {
			assertThat(refreshed.authScheme().value()).isEqualTo("FRESH_TOKEN");
			assertThat(refreshed.secondaryAuthScheme()).isEqualTo(secondary);
		}).verifyComplete();
	}

	@Test
	void refreshAuthKeepsTheStoredTokenWhenTheTokenEndpointFails() {
		mockWebServer.enqueue(new MockResponse().setResponseCode(500));
		SecurityScheme stored = SecurityScheme.bearer("STORED");
		ScanConfiguration config = config(clientCredentials(), stored, null);

		StepVerifier.create(fetcher.refreshAuth(config))
			.assertNext((refreshed) -> assertThat(refreshed.authScheme()).isEqualTo(stored))
			.verifyComplete();
	}

	@Test
	void refreshAuthLeavesAConfigurationWithoutOauth2Untouched() {
		ScanConfiguration config = config(null, SecurityScheme.bearer("STATIC"), null);

		StepVerifier.create(fetcher.refreshAuth(config)).expectNext(config).verifyComplete();
		assertThat(mockWebServer.getRequestCount()).isZero();
	}

	private static ScanConfiguration config(OAuth2Config oauth2, SecurityScheme primary, SecurityScheme secondary) {
		return new ScanConfiguration(List.of(), List.of(), 10, 5000, 10000, false, "json", primary, secondary, "en",
				false, GatewayType.AUTO, null, null, oauth2, null, null);
	}

	private OAuth2Config clientCredentials() {
		return new OAuth2Config(tokenUrl, "test-client", "test-secret", "client_credentials", null, null);
	}

	@Test
	void testFetchTokens_EmptyCredentials() {
		OAuth2Config config = new OAuth2Config(tokenUrl, "test-client", "test-secret", "password", List.of(), null);

		StepVerifier.create(fetcher.fetchTokens(config))
			.assertNext((tokens) -> assertThat(tokens).isEmpty())
			.verifyComplete();
	}

	@Test
	void requestsTheConfiguredScope() throws InterruptedException {
		mockWebServer.enqueue(new MockResponse().setResponseCode(200)
			.setHeader("Content-Type", "application/json")
			.setBody("{\"access_token\": \"TOKEN\", \"token_type\": \"Bearer\"}"));
		OAuth2Config config = new OAuth2Config(tokenUrl, "test-client", "test-secret", "client_credentials", null,
				"openid chat_room_read");

		StepVerifier.create(fetcher.fetchTokens(config)).expectNextCount(1).verifyComplete();
		assertThat(mockWebServer.takeRequest().getBody().readUtf8()).contains("scope=openid+chat_room_read");
	}

	@Test
	void requestsNoScopeWhenNoneIsConfigured() throws InterruptedException {
		mockWebServer.enqueue(new MockResponse().setResponseCode(200)
			.setHeader("Content-Type", "application/json")
			.setBody("{\"access_token\": \"TOKEN\", \"token_type\": \"Bearer\"}"));

		StepVerifier.create(fetcher.fetchTokens(clientCredentials())).expectNextCount(1).verifyComplete();
		assertThat(mockWebServer.takeRequest().getBody().readUtf8()).doesNotContain("scope=");
	}

	@Test
	void aBlankScopeMeansNoScope() {
		assertThat(new OAuth2Config(tokenUrl, "c", "s", "client_credentials", null, "  ").scope()).isNull();
		assertThat(new OAuth2Config(tokenUrl, "c", "s", "client_credentials", null, " openid ").scope())
			.isEqualTo("openid");
	}

}

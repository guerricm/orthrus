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

package ch.nexsol.orthrusdast.web;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import reactor.core.publisher.Mono;
import reactor.netty.DisposableServer;
import reactor.netty.http.server.HttpServer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.csrf;

/**
 * The editor can check a plan before saving it: the discovery is dry-run against the
 * target, and a token is requested with the OAuth2 settings. Both report in a fragment,
 * and the OAuth2 one never shows the token value. An embedded reactor-netty server stands
 * for the target and the identity provider.
 */
@SpringBootTest(properties = {
		"spring.r2dbc.url=r2dbc:h2:mem:///planconfigcheckdb;MODE=PostgreSQL;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE",
		"spring.r2dbc.username=sa", "spring.r2dbc.password=" })
@AutoConfigureWebTestClient
class PlanConfigurationCheckTest {

	private static final String OPENAPI = """
			{"openapi":"3.0.0","info":{"title":"Pets","version":"1"},
			"paths":{"/pets":{"get":{"responses":{"200":{"description":"ok"}}}},
			"/pets/{id}":{"delete":{"parameters":[{"name":"id","in":"path","required":true,
			"schema":{"type":"string"}}],"responses":{"204":{"description":"ok"}}}}}}
			""";

	@Autowired
	private WebTestClient webTestClient;

	private DisposableServer server;

	private String base;

	@BeforeEach
	void setUp() {
		this.server = HttpServer.create()
			.port(0)
			.route((routes) -> routes
				.get("/openapi.json",
						(request, response) -> response.header("Content-Type", "application/json")
							.sendString(Mono.just(OPENAPI)))
				.post("/token",
						(request, response) -> response.header("Content-Type", "application/json")
							.sendString(Mono.just("{\"access_token\":\"" + jwt("openid chat_room_read", 4102444800L)
									+ "\",\"token_type\":\"Bearer\"}")))
				.post("/token-denied", (request, response) -> response.status(401).send()))
			.bindNow();
		this.base = "http://localhost:" + this.server.port();
	}

	@AfterEach
	void tearDown() {
		this.server.disposeNow();
	}

	@Test
	@WithMockUser(roles = "ADMIN")
	void aReachableSpecReportsTheDiscoveredOperations() {
		MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
		form.add("target", this.base + "/openapi.json");
		form.add("discovererId", "openapi");

		String body = post("/plans/check-config", form);

		assertThat(body).contains("Configuration OK.").contains("2 operation(s) discovered").contains("/pets");
	}

	@Test
	@WithMockUser(roles = "ADMIN")
	void anUnreachableTargetReportsTheFailure() {
		int port = this.server.port();
		this.server.disposeNow();
		MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
		form.add("target", "http://localhost:" + port + "/openapi.json");
		form.add("discovererId", "openapi");

		assertThat(post("/plans/check-config", form)).contains("Configuration check failed.");
	}

	@Test
	@WithMockUser(roles = "ADMIN")
	void aMissingTargetOrDiscovererIsReportedWithoutProbing() {
		MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
		form.add("target", "");
		assertThat(post("/plans/check-config", form)).contains("Enter a target first.");

		form.set("target", this.base + "/openapi.json");
		form.add("discovererId", "nope");
		assertThat(post("/plans/check-config", form)).contains("Choose a discovery mode first.");
	}

	@Test
	@WithMockUser(roles = "ADMIN")
	void anIssuedTokenReportsItsScopesButNeverItsValue() {
		MultiValueMap<String, String> form = oauth2Form(this.base + "/token");

		String body = post("/plans/check-oauth2", form);

		assertThat(body).contains("OAuth2 OK.")
			.contains("1 token(s) issued")
			.contains("openid chat_room_read")
			.contains("2100-01-01T00:00:00Z")
			.doesNotContain("eyJ");
	}

	@Test
	@WithMockUser(roles = "ADMIN")
	void aRefusedTokenRequestIsReported() {
		assertThat(post("/plans/check-oauth2", oauth2Form(this.base + "/token-denied")))
			.contains("OAuth2 check failed.")
			.contains("Token request failed");
	}

	@Test
	@WithMockUser(roles = "ADMIN")
	void incompleteOauth2SettingsAreReportedWithoutRequesting() {
		MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
		form.add("oauth2Url", this.base + "/token");

		assertThat(post("/plans/check-oauth2", form)).contains("choose a grant type first");
	}

	private static MultiValueMap<String, String> oauth2Form(String tokenUrl) {
		MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
		form.add("oauth2Url", tokenUrl);
		form.add("oauth2Grant", "client_credentials");
		form.add("oauth2ClientId", "orthrus");
		form.add("oauth2ClientSecret", "s3cret");
		form.add("oauth2Scope", "openid");
		return form;
	}

	/**
	 * An unsigned JWT whose payload carries the given scope and expiry; the check only
	 * decodes the payload, so no signature is needed.
	 * @param scope the scope claim
	 * @param exp the expiry, as epoch seconds
	 * @return the token
	 */
	private static String jwt(String scope, long exp) {
		Base64.Encoder enc = Base64.getUrlEncoder().withoutPadding();
		String header = enc.encodeToString("{\"alg\":\"none\"}".getBytes(StandardCharsets.UTF_8));
		String payload = enc
			.encodeToString(("{\"scope\":\"" + scope + "\",\"exp\":" + exp + "}").getBytes(StandardCharsets.UTF_8));
		return header + "." + payload + ".sig";
	}

	private String post(String uri, MultiValueMap<String, String> form) {
		return this.webTestClient.mutateWith(csrf())
			.post()
			.uri(uri)
			.body(BodyInserters.fromFormData(form))
			.exchange()
			.expectStatus()
			.isOk()
			.expectBody(String.class)
			.returnResult()
			.getResponseBody();
	}

}

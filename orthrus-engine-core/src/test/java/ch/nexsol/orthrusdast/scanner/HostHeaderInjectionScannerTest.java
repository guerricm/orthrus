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

import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import okhttp3.mockwebserver.SocketPolicy;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;

import ch.nexsol.orthrus.protocol.node.RiskLevel;
import ch.nexsol.orthrus.protocol.node.Vulnerability;
import ch.nexsol.orthrusdast.config.OrthrusProperties;
import ch.nexsol.orthrusdast.http.ScanHttpClient;
import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.scanner.oast.OastService;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A reverse proxy commonly answers an unknown Host with a redirect to that host. The
 * scanner must judge the target's real answer: following the redirect makes the client
 * fail on the injected domain, and that client-side error must never be read as the
 * server reflecting the payload.
 */
class HostHeaderInjectionScannerTest {

	private static final String OAST_DOMAIN = "abc123.oast.invalid";

	private MockWebServer server;

	private String target;

	private String targetHost;

	@BeforeEach
	void setUp() throws IOException {
		this.server = new MockWebServer();
		this.server.start();
		this.target = this.server.url("/api/pet").toString();
		this.targetHost = this.server.getHostName() + ":" + this.server.getPort();
	}

	@AfterEach
	void tearDown() throws IOException {
		this.server.shutdown();
	}

	@Test
	void aProxyRedirectingToTheInjectedHostIsReportedFromTheRealResponseNotFromTheClientError() {
		serve((request, injected) -> new MockResponse().setResponseCode(301)
			.setHeader("Location", "http://" + injected + "/api/pet"));

		List<Vulnerability> findings = scan();

		assertThat(findings).extracting(Vulnerability::name)
			.doesNotContain("Host Header Injection - Content Reflection");
		assertThat(findings).singleElement().satisfies((vuln) -> {
			assertThat(vuln.name()).isEqualTo("Host Header Injection - Reflected in Redirect");
			assertThat(vuln.riskLevel()).isEqualTo(RiskLevel.LOW);
			assertThat(vuln.evidence()).contains("Location").contains(OAST_DOMAIN);
		});
	}

	@Test
	void aBodyReflectingTheInjectedHostIsStillReported() {
		serve((request, injected) -> new MockResponse().setBody("Reset link: https://" + injected + "/reset?t=1"));

		assertThat(scan()).extracting(Vulnerability::name).contains("Host Header Injection - Content Reflection");
	}

	@Test
	void aTargetDroppingTheConnectionOnTheInjectedHostIsNotRetried() {
		serve((request, injected) -> new MockResponse().setSocketPolicy(SocketPolicy.DISCONNECT_AFTER_REQUEST));

		assertThat(scan()).isEmpty();
		// One request per injection point, none of them retried.
		assertThat(this.server.getRequestCount()).isEqualTo(2);
	}

	@Test
	void aTargetIgnoringTheHostHeaderYieldsNothing() {
		serve((request, injected) -> new MockResponse().setBody("{\"id\":1}"));

		assertThat(scan()).isEmpty();
	}

	/**
	 * Answers normally for the real host, and through the responder when a request
	 * carries the injected domain in Host or X-Forwarded-Host.
	 * @param responder the answer to an injected request
	 */
	private void serve(Responder responder) {
		this.server.setDispatcher(new Dispatcher() {
			@Override
			public MockResponse dispatch(RecordedRequest request) {
				String host = request.getHeader("Host");
				String forwarded = request.getHeader("X-Forwarded-Host");
				if (OAST_DOMAIN.equals(host) || OAST_DOMAIN.equals(forwarded)) {
					return responder.respond(request, OAST_DOMAIN);
				}
				return new MockResponse().setBody("{\"id\":1}");
			}
		});
	}

	private List<Vulnerability> scan() {
		OrthrusProperties properties = new OrthrusProperties();
		properties.getHttp().setRetryBackoffMs(1);
		properties.getHttp().setRetryMaxBackoffMs(2);
		properties.getHttp().setRequestTimeoutMs(3000);
		// Production follows redirects for ordinary probes.
		WebClient following = WebClient.builder()
			.clientConnector(new ReactorClientHttpConnector(HttpClient.create().followRedirect(true)))
			.build();
		ScanHttpClient httpClient = new ScanHttpClient(following, WebClient.create(), properties);
		HostHeaderInjectionScanner scanner = new HostHeaderInjectionScanner(httpClient, new StubOast());
		return scanner.scan(Operation.simple(this.target, HttpMethod.GET)).collectList().block();
	}

	private interface Responder {

		MockResponse respond(RecordedRequest request, String injectedHost);

	}

	private static final class StubOast implements OastService {

		@Override
		public boolean isEnabled() {
			return false;
		}

		@Override
		public Mono<OastSession> createSession() {
			return Mono.just(new OastSession("c", OAST_DOMAIN, "k"));
		}

		@Override
		public Flux<OastInteraction> pollInteractions(OastSession session) {
			return Flux.empty();
		}

	}

}

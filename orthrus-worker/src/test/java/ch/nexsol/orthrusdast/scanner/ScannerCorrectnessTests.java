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

import ch.nexsol.orthrusdast.http.ScanHttpClient;
import ch.nexsol.orthrusdast.model.GatewayType;
import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.ScanConfiguration;
import ch.nexsol.orthrusdast.model.SecurityScheme;
import ch.nexsol.orthrusdast.model.Vulnerability;
import ch.nexsol.orthrusdast.scanner.payload.PayloadMutator;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.web.reactive.function.client.WebClient;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Focused tests proving the scanner correctness fixes: false-positive reduction (BOLA
 * differential, baseline-validated time-based detection), the real payload mutator,
 * header-injection safety, and the externalized SQL error signatures.
 */
class ScannerCorrectnessTests {

	private MockWebServer mockWebServer;

	private ScanHttpClient httpClient;

	private String baseUrl;

	@BeforeEach
	void setUp() throws IOException {
		mockWebServer = new MockWebServer();
		mockWebServer.start();
		baseUrl = mockWebServer.url("/").toString();
		if (baseUrl.endsWith("/")) {
			baseUrl = baseUrl.substring(0, baseUrl.length() - 1);
		}
		httpClient = new ScanHttpClient(WebClient.create());
	}

	@AfterEach
	void tearDown() throws IOException {
		mockWebServer.shutdown();
	}

	// ----- DetectionUtils (pure heuristics) -----

	@Test
	void timeBasedHitRespectsBaselineAndStatusGuards() {
		// Clear delay over a fast baseline -> hit.
		assertThat(DetectionUtils.isTimeBasedHit(5000, 100, 200)).isTrue();
		// Same delay but the endpoint is naturally slow -> not a hit (FP suppression).
		assertThat(DetectionUtils.isTimeBasedHit(5000, 4000, 200)).isFalse();
		// Gateway timeouts and client errors are never hits.
		assertThat(DetectionUtils.isTimeBasedHit(9000, 100, 504)).isFalse();
		assertThat(DetectionUtils.isTimeBasedHit(9000, 100, 400)).isFalse();
	}

	@Test
	void containsAnyMatchesSignaturesCaseInsensitively() {
		List<String> sigs = List.of("sql syntax", "ora-00933");
		assertThat(DetectionUtils.containsAny("You have an error in your SQL SYNTAX", sigs)).isTrue();
		assertThat(DetectionUtils.containsAny("all good", sigs)).isFalse();
		assertThat(DetectionUtils.containsAny(null, sigs)).isFalse();
	}

	// ----- PayloadMutator (real escaping) -----

	@Test
	void payloadMutatorEscapesJsonAndXml() {
		PayloadMutator mutator = new PayloadMutator();
		assertThat(mutator.mutate("\" OR 1=1", PayloadMutator.Context.JSON_BODY)).isEqualTo("\\\" OR 1=1");
		assertThat(mutator.mutate("<script>", PayloadMutator.Context.XML_BODY)).isEqualTo("&lt;script&gt;");
		// URL params are left raw (WebClient encodes them).
		assertThat(mutator.mutate("a&b", PayloadMutator.Context.URL_PARAM)).isEqualTo("a&b");
	}

	// ----- InjectionHelper (header safety + new body coverage) -----

	@Test
	void injectionHelperNeverOverwritesAuthorizationHeader() {
		Operation op = new Operation(baseUrl + "/users", HttpMethod.GET, Map.of("Authorization", "Bearer real-token"),
				Map.of("q", "x"), null, List.<String>of(), List.<String>of(), null);

		List<InjectionHelper.InjectionTest> tests = InjectionHelper.generateInjectedOperations(op, "PAYLOAD")
			.collectList()
			.block();

		assertThat(tests).isNotNull();
		assertThat(tests).noneMatch((t) -> t.injectionPoint().contains("Authorization"));
		assertThat(tests).anyMatch((t) -> t.injectionPoint().contains("User-Agent"));
		// The real Authorization header must survive on every generated operation.
		assertThat(tests)
			.allMatch((t) -> "Bearer real-token".equals(t.mutatedOperation().headers().get("Authorization")));
	}

	@Test
	void injectionHelperProducesRawJsonBreakoutVariant() {
		Operation op = new Operation(baseUrl + "/users", HttpMethod.POST, Map.of("Content-Type", "application/json"),
				Map.<String, String>of(), "{\"name\":\"bob\"}", List.<String>of(), List.<String>of(), null);

		List<InjectionHelper.InjectionTest> tests = InjectionHelper.generateInjectedOperations(op, "a\"b")
			.collectList()
			.block();

		assertThat(tests).isNotNull();
		InjectionHelper.InjectionTest raw = tests.stream()
			.filter((t) -> t.injectionPoint().contains("raw breakout"))
			.findFirst()
			.orElse(null);
		assertThat(raw).isNotNull();
		// The raw breakout splices the unescaped payload (with its quote) into the value.
		assertThat(raw.mutatedOperation().body()).contains("a\"b");
	}

	@Test
	void injectionHelperInjectsIntoXmlTextNodes() {
		Operation op = new Operation(baseUrl + "/data", HttpMethod.POST, Map.of("Content-Type", "application/xml"),
				Map.<String, String>of(), "<order><item>book</item></order>", List.<String>of(), List.<String>of(),
				null);

		List<InjectionHelper.InjectionTest> tests = InjectionHelper.generateInjectedOperations(op, "<x>")
			.collectList()
			.block();

		assertThat(tests).isNotNull();
		InjectionHelper.InjectionTest xml = tests.stream()
			.filter((t) -> t.injectionPoint().startsWith("XML Body Text Node"))
			.findFirst()
			.orElse(null);
		assertThat(xml).isNotNull();
		// Payload is XML-escaped so the document stays well-formed.
		assertThat(xml.mutatedOperation().body()).contains("&lt;x&gt;");
	}

	// ----- BolaScanner (differential detection) -----

	@Test
	void bolaFlagsDistinctObjectVersusControl() {
		BolaScanner scanner = new BolaScanner(httpClient);
		Operation op = new Operation(baseUrl + "/invoices/100", HttpMethod.GET, Map.<String, String>of(),
				Map.<String, String>of(), null, List.<String>of(), List.<String>of(), null);

		mockWebServer.setDispatcher(new Dispatcher() {
			@Override
			public MockResponse dispatch(RecordedRequest request) {
				String path = request.getPath();
				if (path.endsWith("/910087654321")) {
					// Control: non-existent object.
					return new MockResponse().setResponseCode(404).setBody("Not Found");
				}
				// Tampered neighbour returns a distinct, object-specific body.
				return new MockResponse().setResponseCode(200)
					.setBody("{\"invoice\":\"acme-corp-confidential\",\"amount\":4200,\"owner\":\"alice\"}");
			}
		});

		List<Vulnerability> vulns = scanner.scan(op).collectList().block();
		assertThat(vulns).isNotEmpty();
		assertThat(vulns.get(0).cwe().getId()).isEqualTo(639);
	}

	@Test
	void bolaDoesNotFlagGenericTemplateResponse() {
		BolaScanner scanner = new BolaScanner(httpClient);
		Operation op = new Operation(baseUrl + "/invoices/100", HttpMethod.GET, Map.<String, String>of(),
				Map.<String, String>of(), null, List.<String>of(), List.<String>of(), null);

		// Every id (including the non-existent control) returns the same generic page.
		mockWebServer.setDispatcher(new Dispatcher() {
			@Override
			public MockResponse dispatch(RecordedRequest request) {
				return new MockResponse().setResponseCode(200)
					.setBody("{\"status\":\"ok\",\"message\":\"generic response template body\"}");
			}
		});

		List<Vulnerability> vulns = scanner.scan(op).collectList().block();
		assertThat(vulns).isEmpty();
	}

	// ----- CrossUserBolaScanner (A/B comparison) -----

	@Test
	void crossUserBolaConfirmsWhenUserBSeesSameObject() {
		CrossUserBolaScanner scanner = new CrossUserBolaScanner(httpClient);
		SecurityScheme userA = SecurityScheme.bearer("TOKEN_A");
		SecurityScheme userB = SecurityScheme.bearer("TOKEN_B");
		ScanConfiguration config = new ScanConfiguration(List.<String>of(), List.<String>of(), 10, 5000, 10000, false,
				"json", userA, userB, "en", false, GatewayType.AUTO, null, null, null, null);

		Operation op = new Operation(baseUrl + "/invoices/123", HttpMethod.GET, Map.<String, String>of(),
				Map.<String, String>of(), null, List.of("bearerAuth"), List.<String>of(), userA);

		// Both users receive the same object: confirmed cross-user access.
		mockWebServer.setDispatcher(new Dispatcher() {
			@Override
			public MockResponse dispatch(RecordedRequest request) {
				return new MockResponse().setResponseCode(200).setBody("{\"invoiceId\": 123, \"amount\": 100}");
			}
		});

		List<Vulnerability> vulns = scanner.scan(op, config).collectList().block();
		assertThat(vulns).hasSize(1);
		assertThat(vulns.get(0).confidence()).isEqualTo(Vulnerability.Confidence.HIGH);
	}

	@Test
	void crossUserBolaIgnoresWhenUserBIsForbidden() {
		CrossUserBolaScanner scanner = new CrossUserBolaScanner(httpClient);
		SecurityScheme userA = SecurityScheme.bearer("TOKEN_A");
		SecurityScheme userB = SecurityScheme.bearer("TOKEN_B");
		ScanConfiguration config = new ScanConfiguration(List.<String>of(), List.<String>of(), 10, 5000, 10000, false,
				"json", userA, userB, "en", false, GatewayType.AUTO, null, null, null, null);

		Operation op = new Operation(baseUrl + "/invoices/123", HttpMethod.GET, Map.<String, String>of(),
				Map.<String, String>of(), null, List.of("bearerAuth"), List.<String>of(), userA);

		mockWebServer.setDispatcher(new Dispatcher() {
			@Override
			public MockResponse dispatch(RecordedRequest request) {
				String auth = request.getHeader("Authorization");
				if (auth != null && auth.contains("TOKEN_B")) {
					return new MockResponse().setResponseCode(403).setBody("Forbidden");
				}
				return new MockResponse().setResponseCode(200).setBody("{\"invoiceId\": 123, \"amount\": 100}");
			}
		});

		List<Vulnerability> vulns = scanner.scan(op, config).collectList().block();
		assertThat(vulns).isEmpty();
	}

}

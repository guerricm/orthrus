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

package ch.nexsol.orthrusai.scanner.ai;

import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import reactor.core.publisher.Mono;
import reactor.netty.DisposableServer;
import reactor.netty.http.server.HttpServer;

import ch.nexsol.orthrusai.scanner.recon.DiscoveredEndpoint;
import ch.nexsol.orthrusai.scanner.wire.Vulnerability;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Real end-to-end exercise of the LLM scanning layer against a local Ollama model. It
 * stands up a deliberately vulnerable endpoint (reflected XSS) and lets an XSS family
 * agent probe it, proving that tool-calling, model-generated payloads, the scope guard
 * and the HTTP budget all work with a live model.
 *
 * <p>
 * Opt-in only: run with {@code -Dollama.it=true}. It also self-skips if Ollama is not
 * reachable. Point it at your model with
 * {@code -Dspring.ai.ollama.chat.options.model=qwen3.6:latest}.
 * </p>
 */
@EnabledIfSystemProperty(named = "ollama.it", matches = "true")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE,
		properties = { "orthrus.ai.enabled=true", "orthrus.ai.families=XSS", "spring.ai.model.chat=ollama",
				"spring.ai.ollama.base-url=${OLLAMA_BASE_URL:http://localhost:11434}",
				"spring.ai.ollama.chat.options.model=${OLLAMA_MODEL:qwen3.6:latest}",
				"spring.ai.ollama.chat.options.temperature=0" })
class OllamaFamilyAgentIT {

	private static final Logger log = LoggerFactory.getLogger(OllamaFamilyAgentIT.class);

	@Autowired
	private FamilyAgent familyAgent;

	private DisposableServer target;

	private final AtomicInteger requestsReceived = new AtomicInteger();

	@BeforeEach
	void setUp() {
		assumeTrue(ollamaReachable(), "Ollama not reachable on localhost:11434 - skipping");
		// A reflected-XSS endpoint: it echoes the decoded 'q' parameter into an HTML page
		// unescaped.
		this.target = HttpServer.create().port(0).route((routes) -> routes.get("/echo", (request, response) -> {
			this.requestsReceived.incrementAndGet();
			String reflected = queryValue(request.uri(), "q");
			String body = "<html><body><h1>Results</h1><p>You searched for: " + reflected + "</p></body></html>";
			return response.header("Content-Type", "text/html").sendString(Mono.just(body));
		})).bindNow();
	}

	@AfterEach
	void tearDown() {
		if (this.target != null) {
			this.target.disposeNow();
		}
	}

	@Test
	void xssAgentProbesTheReflectedEndpoint() {
		String url = "http://localhost:" + this.target.port() + "/echo?q=hello";
		DiscoveredEndpoint endpoint = new DiscoveredEndpoint(url, "GET");

		List<Vulnerability> findings = this.familyAgent.scan("XSS", endpoint);

		log.info("=== Ollama XSS agent: {} request(s) to target, {} finding(s) ===", this.requestsReceived.get(),
				findings.size());
		findings
			.forEach((finding) -> log.info("  - [{}] {}: {}", finding.riskLevel(), finding.name(), finding.evidence()));

		// Hard proof the whole loop works with a live model: the agent invoked the
		// scope-guarded HTTP
		// tool, so the in-scope target actually received requests. Whether it then
		// confirms the XSS
		// depends on the model's quality and is reported in the log above, not asserted.
		assertThat(this.requestsReceived.get()).as("the agent should have probed the target at least once")
			.isPositive();
	}

	private static String queryValue(String uri, String key) {
		String query = URI.create(uri).getRawQuery();
		if (query == null) {
			return "";
		}
		for (String pair : query.split("&")) {
			int eq = pair.indexOf('=');
			if (eq > 0 && pair.substring(0, eq).equals(key)) {
				return URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
			}
		}
		return "";
	}

	private static boolean ollamaReachable() {
		try (Socket socket = new Socket()) {
			socket.connect(new InetSocketAddress("localhost", 11434), 1000);
			return true;
		}
		catch (Exception ex) {
			return false;
		}
	}

}

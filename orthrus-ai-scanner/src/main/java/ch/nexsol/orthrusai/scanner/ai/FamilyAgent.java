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

import java.io.InterruptedIOException;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import javax.net.ssl.SSLException;

import io.micrometer.observation.ObservationRegistry;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;
import tools.jackson.databind.ObjectMapper;

import ch.nexsol.orthrus.protocol.ai.Credential;
import ch.nexsol.orthrus.protocol.ai.Credentials;
import ch.nexsol.orthrus.protocol.ai.Endpoint;
import ch.nexsol.orthrus.protocol.node.Vulnerability;
import ch.nexsol.orthrusai.scanner.ai.tool.FindingTool;
import ch.nexsol.orthrusai.scanner.ai.tool.HttpProbeTool;
import ch.nexsol.orthrusai.scanner.config.AiScannerProperties;

/**
 * Runs one family agent against one endpoint. It builds fresh, run-scoped tools (so
 * budgets and findings never leak between endpoints), drives the LLM tool-calling loop
 * synchronously, and returns whatever the agent proved through the finding tool. The
 * blocking call is intentional and confined to the bounded-elastic thread the executor
 * schedules it on.
 */
@Component
@ConditionalOnProperty(prefix = "orthrus.ai", name = "enabled", havingValue = "true")
public class FamilyAgent {

	private static final Logger log = LoggerFactory.getLogger(FamilyAgent.class);

	private final ChatClient chatClient;

	private final WebClient probeWebClient;

	private final ScopeGuard scopeGuard;

	private final ObjectMapper objectMapper;

	private final AiScannerProperties.Budget budget;

	private final AgentActivity agentActivity;

	private static final Pattern PATH_TEMPLATE = Pattern.compile("\\{[^/{}]+}");

	private static final String REFUSED_NOTE = "The endpoint answered the baseline request with 403: it accepts "
			+ "the credentials but refuses this identity. Requests carrying them never reach the endpoint's own "
			+ "processing, so look only for a way around the refusal (other credentials or none, a forged or "
			+ "tampered token, another method or a method override) and at what the refused response itself shows.";

	private volatile WebClient insecureWebClient;

	public FamilyAgent(ChatClient scannerChatClient, WebClient.Builder webClientBuilder, ScopeGuard scopeGuard,
			ObjectMapper objectMapper, AiScannerProperties properties, AgentActivity agentActivity) {
		this.chatClient = scannerChatClient;
		this.agentActivity = agentActivity;
		// Each forged probe has its own URL: observing them would mint one metric tag per
		// payload, so the probe client keeps Boot's settings but not its instrumentation.
		this.probeWebClient = webClientBuilder.observationRegistry(ObservationRegistry.NOOP).build();
		this.scopeGuard = scopeGuard;
		this.objectMapper = objectMapper;
		this.budget = properties.getAi().getBudget();
	}

	/**
	 * Probes one endpoint for one family and returns the findings the agent confirmed.
	 * @param family the scanner family name
	 * @param endpoint the endpoint to probe
	 * @param context the orchestrator's shared target fingerprint, given to the agent as
	 * prior knowledge (may be null or blank)
	 * @param probeConfig the credentials, TLS leniency and timeout to apply to every
	 * probe
	 * @param refused whether the endpoint answered the baseline with a 403, so the agent
	 * is told to look for a way around the refusal
	 * @return the confirmed findings (possibly empty)
	 */
	public List<Vulnerability> scan(String family, Endpoint endpoint, String context, ProbeConfig probeConfig,
			boolean refused) {
		String scannerId = "ai-" + family.toLowerCase();
		RunContext runContext = new RunContext(endpoint.url(), scannerId, this.budget.getMaxHttpCallsPerOperation(),
				this.budget.getMaxToolIterations(), this.budget.getMaxResponseChars(),
				Duration.ofSeconds(this.budget.getEndpointTimeoutSeconds()));
		WebClient probeClient = probeConfig.ignoreSslErrors() ? insecureWebClient() : this.probeWebClient;
		HttpProbeTool httpProbeTool = new HttpProbeTool(probeClient, this.scopeGuard, this.objectMapper, runContext,
				probeConfig.credentials(), Duration.ofMillis(probeConfig.readTimeoutMs()));
		FindingTool findingTool = new FindingTool(runContext, endpoint.url(), endpoint.method());

		String userPrompt = "Test this endpoint: " + endpoint.method() + " " + endpoint.url();
		String shape = describeShape(endpoint);
		if (!shape.isEmpty()) {
			userPrompt += "\n\n" + shape;
		}
		if (context != null && !context.isBlank()) {
			userPrompt += "\n\nPrior recon of the target (shared context): " + context;
		}
		String authNote = describeConfiguredAuth(probeConfig.credentials());
		if (!authNote.isEmpty()) {
			userPrompt += "\n\n" + authNote;
		}
		if (refused) {
			userPrompt += "\n\n" + REFUSED_NOTE;
		}
		this.agentActivity.started();
		try {
			this.chatClient.prompt()
				.system(FamilyPrompts.forFamily(family, this.budget.getMaxToolIterations(),
						this.budget.getMaxHttpCallsPerOperation()))
				.user(userPrompt)
				.tools(httpProbeTool, findingTool)
				.call()
				.content();
		}
		catch (RuntimeException ex) {
			AgentTurnLimitException limit = cause(ex, AgentTurnLimitException.class);
			if (limit != null) {
				log.info("Family agent {} on {} {}: {}", family, endpoint.method(), endpoint.url(), limit.getMessage());
			}
			else if (isInterruption(ex)) {
				log.info("Family agent {} on {} {} interrupted (task cancelled or budget spent)", family,
						endpoint.method(), endpoint.url());
			}
			else {
				log.warn("Family agent {} failed on {} {}: {}", family, endpoint.method(), endpoint.url(),
						ex.getMessage());
			}
		}
		finally {
			this.agentActivity.finished();
		}
		log.info("Family {} on {} {} used {} HTTP call(s), {} finding(s)", family, endpoint.method(), endpoint.url(),
				runContext.httpCallsUsed(), runContext.findings().size());
		return runContext.findings();
	}

	/**
	 * Sends the unmodified request once, with the configured credentials, to learn
	 * whether the endpoint accepts the identity at all. Path templates are filled with a
	 * placeholder: an authorization layer answers before the identifier is ever looked
	 * up.
	 * @param endpoint the endpoint to probe
	 * @param probeConfig the credentials, TLS leniency and timeout to apply
	 * @return the response status, or empty when no response came back
	 */
	public Mono<Integer> baselineStatus(Endpoint endpoint, ProbeConfig probeConfig) {
		WebClient client = probeConfig.ignoreSslErrors() ? insecureWebClient() : this.probeWebClient;
		Duration timeout = Duration.ofMillis(probeConfig.readTimeoutMs());
		return Mono.defer(() -> {
			String url = Credentials.withQueryCredentials(PATH_TEMPLATE.matcher(endpoint.url()).replaceAll("1"),
					probeConfig.credentials());
			WebClient.RequestBodySpec spec = client.method(HttpMethod.valueOf(endpoint.method())).uri(url);
			Credentials.applyHeaderAndCookie(spec, probeConfig.credentials());
			return spec.exchangeToMono((response) -> response.releaseBody().thenReturn(response.statusCode().value()));
		}).timeout(timeout).onErrorResume((ex) -> {
			log.debug("Baseline of {} {} got no response: {}", endpoint.method(), endpoint.url(), ex.getMessage());
			return Mono.empty();
		});
	}

	/**
	 * Describes the operation's shape read from the API spec, its parameters and request
	 * body, so the agent forges realistic requests instead of guessing field names and
	 * types. Empty when recon found no shape.
	 * @param endpoint the endpoint being scanned
	 * @return a note for the prompt, or an empty string when nothing is known
	 */
	private static String describeShape(Endpoint endpoint) {
		boolean hasParams = !endpoint.parameters().isEmpty();
		boolean hasBody = endpoint.requestBodySchema() != null && !endpoint.requestBodySchema().isBlank();
		if (!hasParams && !hasBody) {
			return "";
		}
		StringBuilder sb = new StringBuilder(
				"Operation shape from the API spec (use real values, do not invent field names):");
		for (Endpoint.Parameter p : endpoint.parameters()) {
			sb.append("\n- ")
				.append(p.in())
				.append(" parameter ")
				.append(p.name())
				.append(" (")
				.append(p.type())
				.append(p.required() ? ", required" : "")
				.append(")");
		}
		if (hasBody) {
			sb.append("\n- request body: ").append(endpoint.requestBodySchema());
		}
		return sb.toString();
	}

	/**
	 * Describes the credentials the operator configured, by location and name only, so
	 * the agent knows the endpoint is authenticated. Without this the credentials are
	 * attached silently and an agent whose subject depends on them (JWT, BOLA) would
	 * wrongly judge its subject absent and stop. Values are never exposed.
	 * @param credentials the configured credentials, may be empty
	 * @return a note for the prompt, or an empty string when none are configured
	 */
	private static String describeConfiguredAuth(List<Credential> credentials) {
		if (credentials == null || credentials.isEmpty()) {
			return "";
		}
		String summary = credentials.stream()
			.filter((c) -> c != null && c.name() != null)
			.map((c) -> ((c.location() != null) ? c.location().toUpperCase(Locale.ROOT) : "HEADER") + " " + c.name())
			.distinct()
			.collect(Collectors.joining(", "));
		if (summary.isEmpty()) {
			return "";
		}
		return "The operator configured credentials, attached automatically to every request (" + summary
				+ "). Treat the endpoint as authenticated: your subject may apply even if the baseline "
				+ "response shows nothing.";
	}

	/**
	 * Whether the agent stopped because its thread was interrupted: the task was
	 * cancelled or spent its budget, and Reactor interrupts the agents still running. The
	 * blocking call surfaces that as an exception whose message is usually empty.
	 * @param ex the exception the agent loop ended with
	 * @return true when it is an interruption rather than a failure
	 */
	private static boolean isInterruption(Throwable ex) {
		if (Thread.currentThread().isInterrupted()) {
			return true;
		}
		return causedBy(ex, InterruptedException.class) || causedBy(ex, InterruptedIOException.class);
	}

	private static boolean causedBy(Throwable ex, Class<? extends Throwable> type) {
		return cause(ex, type) != null;
	}

	private static <T extends Throwable> T cause(Throwable ex, Class<T> type) {
		for (Throwable cause = ex; cause != null; cause = cause.getCause()) {
			if (type.isInstance(cause)) {
				return type.cast(cause);
			}
		}
		return null;
	}

	/**
	 * A probe client that trusts any certificate, built once on demand. Used only when
	 * the operator opted into ignoring SSL errors for the target (e.g. self-signed
	 * staging).
	 * @return the insecure web client
	 */
	private WebClient insecureWebClient() {
		WebClient client = this.insecureWebClient;
		if (client == null) {
			synchronized (this) {
				client = this.insecureWebClient;
				if (client == null) {
					try {
						SslContext sslContext = SslContextBuilder.forClient()
							.trustManager(InsecureTrustManagerFactory.INSTANCE)
							.build();
						HttpClient httpClient = HttpClient.create().secure((sslSpec) -> sslSpec.sslContext(sslContext));
						client = WebClient.builder()
							.clientConnector(new ReactorClientHttpConnector(httpClient))
							.build();
					}
					catch (SSLException ex) {
						log.warn("Could not build an SSL-lenient client ({}); using the default probe client",
								ex.getMessage());
						client = this.probeWebClient;
					}
					this.insecureWebClient = client;
				}
			}
		}
		return client;
	}

}

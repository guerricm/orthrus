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

package ch.nexsol.orthrusai.orchestrator.recon;

import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import ch.nexsol.orthrusai.orchestrator.model.Credential;
import ch.nexsol.orthrusai.orchestrator.model.Endpoint;
import ch.nexsol.orthrusai.orchestrator.model.ReconResult;

/**
 * The orchestrator's recon: fingerprint the target once and map its endpoints. If the
 * target serves an OpenAPI document, its paths and methods become the endpoint list,
 * resolved against the document's {@code servers} base path; otherwise the target URL
 * itself is the single endpoint. Kept deterministic so it works without a model; the LLM
 * planner reuses the same picture.
 */
@Service
public class ReconService {

	private static final Logger log = LoggerFactory.getLogger(ReconService.class);

	private static final int MAX_ENDPOINTS = 50;

	private static final List<String> HTTP_METHODS = List.of("get", "put", "post", "delete", "patch");

	private final WebClient webClient;

	private final ObjectMapper objectMapper;

	public ReconService(WebClient.Builder webClientBuilder, ObjectMapper objectMapper) {
		this.webClient = webClientBuilder.build();
		this.objectMapper = objectMapper;
	}

	/**
	 * Fingerprints the target and discovers its endpoints.
	 * @param target the target URL (an app root or an OpenAPI document)
	 * @return the recon result, never empty (falls back to the target itself)
	 */
	public Mono<ReconResult> discover(String target) {
		return discover(target, null, List.of());
	}

	/**
	 * Fingerprints the target and discovers its endpoints, sending the given credentials
	 * so a protected OpenAPI document can be read, and forcing the base host when the
	 * caller overrides it.
	 * @param target the target URL (an app root or an OpenAPI document)
	 * @param overrideHost the base host to force on discovered endpoints, or null
	 * @param credentials credentials to send while fetching the document
	 * @return the recon result, never empty (falls back to the target itself)
	 */
	public Mono<ReconResult> discover(String target, String overrideHost, List<Credential> credentials) {
		WebClient.RequestHeadersSpec<?> request = this.webClient.get().uri(applyQueryCredentials(target, credentials));
		applyHeaderAndCookieCredentials(request, credentials);
		return request
			.exchangeToMono((response) -> response.bodyToMono(String.class)
				.defaultIfEmpty("")
				.map((body) -> build(target, overrideHost, response, body)))
			.timeout(Duration.ofSeconds(10))
			.onErrorResume((e) -> {
				log.debug("Recon of {} failed ({}); using target as single endpoint", target, e.getMessage());
				return Mono.just(new ReconResult(origin(target), List.of(new Endpoint("GET", target)),
						"Target could not be fingerprinted: " + e.getMessage()));
			});
	}

	private ReconResult build(String target, String overrideHost, ClientResponse response, String body) {
		Parsed parsed = parseOpenApi(target, body);
		List<Endpoint> endpoints = parsed.endpoints().isEmpty() ? List.of(new Endpoint("GET", target))
				: parsed.endpoints();
		String base = parsed.base();
		if (overrideHost != null && !overrideHost.isBlank()) {
			base = rewriteHost(base, overrideHost);
			List<Endpoint> rewritten = new ArrayList<>();
			for (Endpoint e : endpoints) {
				rewritten.add(new Endpoint(e.method(), rewriteHost(e.url(), overrideHost)));
			}
			endpoints = rewritten;
		}
		String context = fingerprint(target, response, endpoints.size());
		return new ReconResult(base, endpoints, context);
	}

	private void applyHeaderAndCookieCredentials(WebClient.RequestHeadersSpec<?> request,
			List<Credential> credentials) {
		for (Credential c : credentials) {
			if (c == null || c.name() == null || c.value() == null) {
				continue;
			}
			String location = (c.location() != null) ? c.location().toUpperCase(Locale.ROOT) : "HEADER";
			if ("COOKIE".equals(location)) {
				request.cookie(c.name(), c.value());
			}
			else if (!"QUERY".equals(location)) {
				request.header(c.name(), c.value().replaceAll("[\\r\\n]", ""));
			}
		}
	}

	private String applyQueryCredentials(String target, List<Credential> credentials) {
		StringBuilder url = new StringBuilder(target);
		boolean hasQuery = target.contains("?");
		for (Credential c : credentials) {
			if (c == null || c.name() == null || c.value() == null) {
				continue;
			}
			if ("QUERY".equalsIgnoreCase(c.location())) {
				url.append(hasQuery ? '&' : '?').append(c.name()).append('=').append(c.value());
				hasQuery = true;
			}
		}
		return url.toString();
	}

	private String rewriteHost(String url, String overrideHost) {
		try {
			URI original = URI.create(url);
			String origin = overrideHost.contains("://") ? overrideHost
					: ((original.getScheme() != null) ? original.getScheme() : "https") + "://" + overrideHost;
			origin = stripTrailingSlash(origin);
			String path = (original.getRawPath() != null) ? original.getRawPath() : "";
			String query = (original.getRawQuery() != null) ? "?" + original.getRawQuery() : "";
			return origin + path + query;
		}
		catch (IllegalArgumentException ex) {
			return url;
		}
	}

	private String fingerprint(String target, ClientResponse response, int endpointCount) {
		HttpHeaders headers = response.headers().asHttpHeaders();
		StringBuilder sb = new StringBuilder();
		sb.append("Target ")
			.append(target)
			.append(" responded HTTP ")
			.append(response.statusCode().value())
			.append(". ");
		appendHeader(sb, headers, "Server");
		appendHeader(sb, headers, "X-Powered-By");
		appendHeader(sb, headers, "Content-Type");
		sb.append(endpointCount).append(" endpoint(s) discovered.");
		return sb.toString();
	}

	private void appendHeader(StringBuilder sb, HttpHeaders headers, String name) {
		String value = headers.getFirst(name);
		if (value != null && !value.isBlank()) {
			sb.append(name).append("=").append(value).append("; ");
		}
	}

	private Parsed parseOpenApi(String target, String body) {
		if (body == null || body.isBlank()) {
			return new Parsed(origin(target), List.of());
		}
		try {
			JsonNode root = this.objectMapper.readTree(body);
			JsonNode paths = root.get("paths");
			boolean looksOpenApi = root.has("openapi") || root.has("swagger");
			if (!looksOpenApi || paths == null || !paths.isObject()) {
				return new Parsed(origin(target), List.of());
			}
			String base = resolveBase(target, root);
			List<Endpoint> endpoints = new ArrayList<>();
			paths.properties().forEach((entry) -> {
				String path = entry.getKey();
				JsonNode methods = entry.getValue();
				for (String method : HTTP_METHODS) {
					if (methods.has(method) && endpoints.size() < MAX_ENDPOINTS) {
						endpoints.add(new Endpoint(method.toUpperCase(Locale.ROOT), base + path));
					}
				}
			});
			log.info("Recon parsed {} endpoint(s) from OpenAPI at {}", endpoints.size(), target);
			return new Parsed(base, endpoints);
		}
		catch (RuntimeException ex) {
			return new Parsed(origin(target), List.of());
		}
	}

	/**
	 * Resolves the base URL that OpenAPI paths are relative to. Honours the document's
	 * {@code servers[0].url} (absolute, or relative to the document's origin), and
	 * otherwise falls back to the document's parent path, so a spec fetched from
	 * {@code https://host/api/v3/openapi.json} yields {@code https://host/api/v3}, not
	 * just {@code https://host}. Getting this wrong makes every probe hit a 404.
	 * @param target the URL the document was fetched from
	 * @param root the parsed OpenAPI document
	 * @return the base URL to prefix paths with, without a trailing slash
	 */
	private String resolveBase(String target, JsonNode root) {
		JsonNode servers = root.get("servers");
		if (servers != null && servers.isArray() && !servers.isEmpty()) {
			JsonNode first = servers.get(0);
			String url = (first != null && first.hasNonNull("url")) ? first.get("url").asString().trim() : "";
			if (!url.isEmpty()) {
				if (url.startsWith("http://") || url.startsWith("https://")) {
					return stripTrailingSlash(url);
				}
				return origin(target) + stripTrailingSlash(url.startsWith("/") ? url : "/" + url);
			}
		}
		return docBase(target);
	}

	private String docBase(String target) {
		try {
			URI uri = URI.create(target);
			String path = uri.getRawPath();
			if (path == null || path.isEmpty() || path.equals("/")) {
				return origin(target);
			}
			int lastSlash = path.lastIndexOf('/');
			String parent = (lastSlash > 0) ? path.substring(0, lastSlash) : "";
			return origin(target) + parent;
		}
		catch (IllegalArgumentException ex) {
			return origin(target);
		}
	}

	private String stripTrailingSlash(String url) {
		return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
	}

	private String origin(String target) {
		try {
			URI uri = URI.create(target);
			String scheme = (uri.getScheme() != null) ? uri.getScheme() : "http";
			int port = uri.getPort();
			String authority = (port != -1) ? uri.getHost() + ":" + port : uri.getHost();
			return scheme + "://" + authority;
		}
		catch (IllegalArgumentException ex) {
			return target;
		}
	}

	private record Parsed(String base, List<Endpoint> endpoints) {
	}

}

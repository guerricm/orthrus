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

package ch.nexsol.orthrus.protocol.ai;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * The lightweight OpenAPI reading shared by the AI services: the document's paths and
 * methods become endpoints, resolved against the right base URL. Deliberately not a full
 * parser; it only needs enough to hand an agent absolute URLs that do not 404.
 *
 * @param baseUrl the base URL the paths were resolved against, without trailing slash
 * @param endpoints the endpoints found, empty when the body is not an OpenAPI document
 */
public record OpenApiEndpoints(String baseUrl, List<Endpoint> endpoints) {

	/**
	 * Upper bound on the endpoints kept from one document, so an agent's budget is not
	 * spread over hundreds of operations.
	 */
	public static final int MAX_ENDPOINTS = 50;

	private static final List<String> HTTP_METHODS = List.of("get", "put", "post", "delete", "patch");

	/**
	 * Reads the endpoints out of a body fetched from {@code target}. Never throws: a body
	 * that is not an OpenAPI document yields no endpoints and the target's origin as
	 * base.
	 * @param objectMapper the JSON reader
	 * @param target the URL the body was fetched from
	 * @param body the response body, may be null
	 * @return the base URL and endpoints
	 */
	public static OpenApiEndpoints parse(ObjectMapper objectMapper, String target, String body) {
		if (body == null || body.isBlank()) {
			return new OpenApiEndpoints(origin(target), List.of());
		}
		try {
			JsonNode root = objectMapper.readTree(body);
			JsonNode paths = root.get("paths");
			boolean looksOpenApi = root.has("openapi") || root.has("swagger");
			if (!looksOpenApi || paths == null || !paths.isObject()) {
				return new OpenApiEndpoints(origin(target), List.of());
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
			return new OpenApiEndpoints(base, endpoints);
		}
		catch (RuntimeException ex) {
			return new OpenApiEndpoints(origin(target), List.of());
		}
	}

	/**
	 * Rewrites the scheme, host and port of a URL, keeping its path and query.
	 * @param url the URL to rewrite
	 * @param overrideHost the host to force, with or without a scheme
	 * @return the rewritten URL, or the original one when it cannot be parsed
	 */
	public static String rewriteHost(String url, String overrideHost) {
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

	/**
	 * The scheme, host and port of a URL.
	 * @param target the URL
	 * @return its origin, or the URL itself when it cannot be parsed
	 */
	public static String origin(String target) {
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
	private static String resolveBase(String target, JsonNode root) {
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

	private static String docBase(String target) {
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

	private static String stripTrailingSlash(String url) {
		return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
	}

}

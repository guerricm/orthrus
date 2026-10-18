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
				JsonNode pathItem = entry.getValue();
				for (String method : HTTP_METHODS) {
					if (pathItem.has(method) && endpoints.size() < MAX_ENDPOINTS) {
						JsonNode op = pathItem.get(method);
						endpoints.add(new Endpoint(method.toUpperCase(Locale.ROOT), base + path,
								readParameters(pathItem, op, root), readRequestBodySchema(op, root)));
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
	 * Upper bound on properties rendered from a body schema, so a large model does not
	 * bloat every agent turn (the whole conversation is resent each turn).
	 */
	private static final int MAX_SCHEMA_PROPERTIES = 24;

	/**
	 * Reads an operation's parameters, merging the path-level parameters that apply to
	 * every method with the operation's own. Operation parameters win on a name/location
	 * clash. Parameters declared as a {@code $ref} to the document's components are
	 * resolved.
	 * @param pathItem the path item node
	 * @param op the operation node
	 * @param root the whole document, for resolving references
	 * @return the parameters, never null
	 */
	private static List<Endpoint.Parameter> readParameters(JsonNode pathItem, JsonNode op, JsonNode root) {
		List<Endpoint.Parameter> params = new ArrayList<>();
		addParameters(params, pathItem.get("parameters"), root);
		addParameters(params, op.get("parameters"), root);
		return params;
	}

	private static void addParameters(List<Endpoint.Parameter> into, JsonNode array, JsonNode root) {
		if (array == null || !array.isArray()) {
			return;
		}
		for (JsonNode entry : array) {
			JsonNode p = resolveRef(entry, root);
			String name = p.hasNonNull("name") ? p.get("name").asString() : null;
			if (name == null) {
				continue;
			}
			String in = p.hasNonNull("in") ? p.get("in").asString() : "query";
			JsonNode schema = p.get("schema");
			String type = (schema != null && schema.hasNonNull("type")) ? schema.get("type").asString()
					: (p.hasNonNull("type") ? p.get("type").asString() : "string");
			boolean required = p.hasNonNull("required") && p.get("required").asBoolean();
			into.removeIf((existing) -> existing.name().equals(name) && existing.in().equals(in));
			into.add(new Endpoint.Parameter(name, in, type, required));
		}
	}

	/**
	 * Reads and renders the JSON request body schema of an operation into a compact,
	 * one-line description, resolving a {@code $ref} on the request body or its schema
	 * against the document's components. Only the first level of properties is rendered.
	 * @param op the operation node
	 * @param root the whole document, for resolving references
	 * @return the rendered schema, or null when there is no JSON body
	 */
	private static String readRequestBodySchema(JsonNode op, JsonNode root) {
		JsonNode requestBody = resolveRef(op.get("requestBody"), root);
		JsonNode content = (requestBody != null) ? requestBody.get("content") : null;
		if (content == null || !content.isObject() || content.isEmpty()) {
			return null;
		}
		JsonNode media = content.has("application/json") ? content.get("application/json")
				: content.properties().iterator().next().getValue();
		JsonNode schema = (media != null) ? media.get("schema") : null;
		if (schema == null) {
			return null;
		}
		return renderObjectSchema(resolveRef(schema, root), root);
	}

	private static String renderObjectSchema(JsonNode schema, JsonNode root) {
		if (schema == null) {
			return null;
		}
		JsonNode properties = schema.get("properties");
		String title = schema.hasNonNull("title") ? schema.get("title").asString() : "";
		if (properties == null || !properties.isObject()) {
			String type = schema.hasNonNull("type") ? schema.get("type").asString() : "object";
			return title.isEmpty() ? type : title + " (" + type + ")";
		}
		List<String> required = requiredNames(schema);
		StringBuilder sb = new StringBuilder();
		if (!title.isEmpty()) {
			sb.append(title).append(' ');
		}
		sb.append("{ ");
		int count = 0;
		for (var entry : properties.properties()) {
			if (count == MAX_SCHEMA_PROPERTIES) {
				sb.append(", ...");
				break;
			}
			if (count > 0) {
				sb.append(", ");
			}
			sb.append(entry.getKey()).append(": ").append(typeOf(entry.getValue(), root));
			if (required.contains(entry.getKey())) {
				sb.append(" (required)");
			}
			count++;
		}
		sb.append(" }");
		return sb.toString();
	}

	private static List<String> requiredNames(JsonNode schema) {
		List<String> names = new ArrayList<>();
		JsonNode required = schema.get("required");
		if (required != null && required.isArray()) {
			for (JsonNode n : required) {
				names.add(n.asString());
			}
		}
		return names;
	}

	private static String typeOf(JsonNode property, JsonNode root) {
		if (property.hasNonNull("$ref")) {
			return refName(property.get("$ref").asString());
		}
		String type = property.hasNonNull("type") ? property.get("type").asString() : "object";
		if ("array".equals(type)) {
			JsonNode items = property.get("items");
			return (items != null) ? "array<" + typeOf(items, root) + ">" : "array";
		}
		return type;
	}

	private static JsonNode resolveRef(JsonNode node, JsonNode root) {
		if (node != null && node.hasNonNull("$ref")) {
			String ref = node.get("$ref").asString();
			if (ref.startsWith("#/")) {
				JsonNode resolved = root;
				for (String segment : ref.substring(2).split("/")) {
					if (resolved == null) {
						return node;
					}
					resolved = resolved.get(segment);
				}
				if (resolved != null) {
					return resolved;
				}
			}
		}
		return node;
	}

	private static String refName(String ref) {
		int slash = ref.lastIndexOf('/');
		return (slash >= 0 && slash < ref.length() - 1) ? ref.substring(slash + 1) : ref;
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

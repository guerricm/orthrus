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

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;

import org.springframework.web.reactive.function.client.WebClient;

/**
 * Applies resolved {@link Credential}s to outgoing requests, the same way on every AI
 * service: header and cookie credentials go on the request, query credentials on the URL.
 */
public final class Credentials {

	private Credentials() {
	}

	/**
	 * Attaches the header and cookie credentials to a request. Query credentials are
	 * ignored here, see {@link #withQueryCredentials(String, List)}.
	 * @param request the request being built
	 * @param credentials the credentials, may be null or empty
	 */
	public static void applyHeaderAndCookie(WebClient.RequestHeadersSpec<?> request, List<Credential> credentials) {
		if (credentials == null) {
			return;
		}
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

	/**
	 * Appends the query credentials to a URL.
	 * @param url the URL to request
	 * @param credentials the credentials, may be null or empty
	 * @return the URL with the query credentials appended
	 */
	public static String withQueryCredentials(String url, List<Credential> credentials) {
		if (credentials == null || credentials.isEmpty()) {
			return url;
		}
		StringBuilder built = new StringBuilder(url);
		boolean hasQuery = url.contains("?");
		for (Credential c : credentials) {
			if (c == null || c.name() == null || c.value() == null || !"QUERY".equalsIgnoreCase(c.location())) {
				continue;
			}
			built.append(hasQuery ? '&' : '?')
				.append(URLEncoder.encode(c.name(), StandardCharsets.UTF_8))
				.append('=')
				.append(URLEncoder.encode(c.value(), StandardCharsets.UTF_8));
			hasQuery = true;
		}
		return built.toString();
	}

}

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

package ch.nexsol.orthrusdast.model;

import java.util.Base64;

/**
 * Represents an authentication scheme to apply to scan requests. Supports Bearer tokens,
 * API keys, Basic auth, and OAuth2.
 */
public record SecurityScheme(AuthType type, String value, String headerName, String paramName,
		ParamLocation paramLocation) {

	public enum AuthType {

		BEARER, API_KEY, BASIC, OAUTH2_CLIENT_CREDENTIALS, OAUTH2_AUTHORIZATION_CODE

	}

	public enum ParamLocation {

		HEADER, QUERY, COOKIE

	}

	/**
	 * Create a Bearer token scheme.
	 */
	public static SecurityScheme bearer(String token) {
		return new SecurityScheme(AuthType.BEARER, token, "Authorization", null, ParamLocation.HEADER);
	}

	/**
	 * Create an API Key scheme (default: header-based).
	 */
	public static SecurityScheme apiKey(String key, String headerName) {
		return new SecurityScheme(AuthType.API_KEY, key, headerName, null, ParamLocation.HEADER);
	}

	/**
	 * Create an API Key scheme placed in a query parameter.
	 */
	public static SecurityScheme apiKeyQuery(String key, String paramName) {
		return new SecurityScheme(AuthType.API_KEY, key, null, paramName, ParamLocation.QUERY);
	}

	/**
	 * Create a Basic Auth scheme from username:password.
	 */
	public static SecurityScheme basic(String username, String password) {
		String encoded = Base64.getEncoder().encodeToString((username + ":" + password).getBytes());
		return new SecurityScheme(AuthType.BASIC, encoded, "Authorization", null, ParamLocation.HEADER);
	}

	/**
	 * Build the Authorization header value for this scheme.
	 */
	public String toAuthorizationHeaderValue() {
		return switch (type) {
			case BEARER -> "Bearer " + value;
			case BASIC -> "Basic " + value;
			case API_KEY -> value;
			case OAUTH2_CLIENT_CREDENTIALS, OAUTH2_AUTHORIZATION_CODE -> "Bearer " + value;
		};
	}
}

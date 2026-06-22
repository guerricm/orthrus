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

import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.springframework.http.HttpMethod;

/**
 * Represents a single API operation (endpoint + method) to be scanned. Aligned with
 * vulnapi's Operation concept.
 */
public record Operation(String url, HttpMethod method, Map<String, String> headers, Map<String, String> queryParams,
		String body, List<String> securityRequirements, List<String> expectedContentTypes, SecurityScheme authScheme,
		String templateUrl, Object sourceNode, List<HttpMethod> supportedMethods) {

	public Operation(String url, HttpMethod method, Map<String, String> headers, Map<String, String> queryParams,
			String body, List<String> securityRequirements, List<String> expectedContentTypes,
			SecurityScheme authScheme, String templateUrl, Object sourceNode) {
		this(url, method, headers, queryParams, body, securityRequirements, expectedContentTypes, authScheme,
				templateUrl, sourceNode, (method != null) ? List.of(method) : Collections.emptyList());
	}

	public Operation(String url, HttpMethod method, Map<String, String> headers, Map<String, String> queryParams,
			String body, List<String> securityRequirements, List<String> expectedContentTypes,
			SecurityScheme authScheme) {
		this(url, method, headers, queryParams, body, securityRequirements, expectedContentTypes, authScheme, url, null,
				(method != null) ? List.of(method) : Collections.emptyList());
	}

	/**
	 * Create a simple operation with just URL and method (for blackbox discovery).
	 */
	public static Operation simple(String url, HttpMethod method) {
		return new Operation(url, method, Collections.emptyMap(), Collections.emptyMap(), null, Collections.emptyList(),
				Collections.emptyList(), null, url, null, (method != null) ? List.of(method) : Collections.emptyList());
	}

	/**
	 * Create an operation with headers (for curl-like discovery).
	 */
	public static Operation withHeaders(String url, HttpMethod method, Map<String, String> headers, String body) {
		return new Operation(url, method, (headers != null) ? headers : Collections.emptyMap(), Collections.emptyMap(),
				body, Collections.emptyList(), Collections.emptyList(), null, url, null,
				(method != null) ? List.of(method) : Collections.emptyList());
	}

	/**
	 * Return a copy of this operation with the given auth scheme applied.
	 */
	public Operation withAuth(SecurityScheme scheme) {
		return new Operation(url, method, headers, queryParams, body, securityRequirements, expectedContentTypes,
				scheme, templateUrl, sourceNode, supportedMethods);
	}
}

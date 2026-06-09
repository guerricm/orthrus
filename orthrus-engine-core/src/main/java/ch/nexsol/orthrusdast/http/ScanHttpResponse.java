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

package ch.nexsol.orthrusdast.http;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;

/**
 * Immutable representation of an HTTP response captured during scanning.
 */
public record ScanHttpResponse(HttpStatusCode statusCode, HttpHeaders headers, String body, long responseTimeMs) {

	/**
	 * Check if the response has a specific header.
	 */
	public boolean hasHeader(String headerName) {
		return headers.getFirst(headerName) != null;
	}

	/**
	 * Get a header value (first value only), or null.
	 */
	public String getHeader(String headerName) {
		return headers.getFirst(headerName);
	}

	/**
	 * Check if the status code is in the 2xx range.
	 */
	public boolean isSuccessful() {
		return statusCode.is2xxSuccessful();
	}

	/**
	 * Check if the body contains a specific string (case-insensitive).
	 */
	public boolean bodyContains(String text) {
		return body != null && body.toLowerCase().contains(text.toLowerCase());
	}

	/**
	 * Check if the body contains a specific string (case-sensitive).
	 */
	public boolean bodyContainsExact(String text) {
		return body != null && body.contains(text);
	}
}

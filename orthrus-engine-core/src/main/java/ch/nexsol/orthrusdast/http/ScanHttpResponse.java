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
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;

/**
 * Immutable representation of an HTTP response captured during scanning.
 *
 * @param statusCode the status
 * @param headers the response headers
 * @param body the response body (possibly truncated)
 * @param responseTimeMs how long the exchange took
 * @param clientError true when the request never got an answer from the target (DNS,
 * connection, timeout) and this response was produced by the client to report it; its
 * body is the client's error message, never target content
 */
public record ScanHttpResponse(HttpStatusCode statusCode, HttpHeaders headers, String body, long responseTimeMs,
		boolean clientError) {

	public ScanHttpResponse(HttpStatusCode statusCode, HttpHeaders headers, String body, long responseTimeMs) {
		this(statusCode, headers, body, responseTimeMs, false);
	}

	/**
	 * A response standing for a request the target never answered.
	 * @param message the client-side failure
	 * @param elapsedMs the time spent before giving up
	 * @return a 503 marked as a client error
	 */
	public static ScanHttpResponse clientError(String message, long elapsedMs) {
		return new ScanHttpResponse(HttpStatus.SERVICE_UNAVAILABLE, new HttpHeaders(), "Error: " + message, elapsedMs,
				true);
	}

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
	 * Check if the target's body contains a specific string (case-insensitive). Always
	 * false for a client error: the client's own message must not pass for a reflection.
	 */
	public boolean bodyContains(String text) {
		return !this.clientError && body != null && body.toLowerCase().contains(text.toLowerCase());
	}

	/**
	 * Check if the target's body contains a specific string (case-sensitive). Always
	 * false for a client error.
	 */
	public boolean bodyContainsExact(String text) {
		return !this.clientError && body != null && body.contains(text);
	}
}

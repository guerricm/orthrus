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
 * connection, timeout) and this response was produced by the client to report it; the
 * client's error message is then {@link #clientMessage()}, and {@link #body()} is empty
 * so no check reads that message as target content
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
	 * The target's body: empty for a client error, whose message is never target content.
	 */
	@Override
	public String body() {
		return this.clientError ? "" : this.body;
	}

	/**
	 * The client's failure message for a client error, for the evidence; null otherwise.
	 */
	public String clientMessage() {
		return this.clientError ? this.body : null;
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
		String targetBody = body();
		return targetBody != null && targetBody.toLowerCase().contains(text.toLowerCase());
	}

	/**
	 * Check if the target's body contains a specific string (case-sensitive). Always
	 * false for a client error.
	 */
	public boolean bodyContainsExact(String text) {
		String targetBody = body();
		return targetBody != null && targetBody.contains(text);
	}
}

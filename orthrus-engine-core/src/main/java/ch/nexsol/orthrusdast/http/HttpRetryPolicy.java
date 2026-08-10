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

import java.time.Duration;
import java.time.ZonedDateTime;
import java.time.format.DateTimeParseException;

import org.springframework.http.HttpHeaders;

import ch.nexsol.orthrusdast.config.OrthrusProperties;

/**
 * Central policy for deciding when an HTTP response warrants a retry and how long to wait
 * before the next attempt.
 *
 * <p>
 * Scanners send payloads strictly sequentially, so a target that starts throttling or
 * blocking mid-scan (429, or a WAF answering 401/403) is the main source of lost
 * coverage: a blocked request that is treated as a final answer produces a false
 * negative. This policy backs off and re-sends those requests instead, honouring a
 * {@code Retry-After} header when the server provides one.
 */
public class HttpRetryPolicy {

	private final int maxRetries;

	private final Duration baseBackoff;

	private final Duration maxBackoff;

	public HttpRetryPolicy(int maxRetries, Duration baseBackoff, Duration maxBackoff) {
		this.maxRetries = maxRetries;
		this.baseBackoff = baseBackoff;
		this.maxBackoff = maxBackoff;
	}

	public static HttpRetryPolicy from(OrthrusProperties.Http http) {
		return new HttpRetryPolicy(http.getMaxRetries(), Duration.ofMillis(http.getRetryBackoffMs()),
				Duration.ofMillis(http.getRetryMaxBackoffMs()));
	}

	public int maxRetries() {
		return maxRetries;
	}

	/**
	 * Classifies an HTTP status code with respect to retry behaviour.
	 * @param status the HTTP status code
	 * @return the classification
	 */
	public static StatusClass classify(int status) {
		return switch (status) {
			// Server temporarily unable to serve the request, or an upstream gateway
			// hiccup. Almost always worth retrying.
			case 500, 502, 503, 504 -> StatusClass.RETRYABLE_TRANSIENT;
			// Explicit throttling.
			case 429 -> StatusClass.RETRYABLE_THROTTLE;
			// A WAF or gateway sitting in front of the target frequently answers 401/403
			// when it decides to block a client that is probing too aggressively. These
			// are retried so a transient block does not mask a real finding; if the
			// target
			// genuinely requires auth the same status simply comes back and is surfaced.
			case 401, 403 -> StatusClass.RETRYABLE_BLOCKING;
			default -> StatusClass.FINAL;
		};
	}

	/**
	 * Whether a response with the given status should be retried.
	 * @param status the HTTP status code
	 * @return true if the request should be re-sent
	 */
	public boolean isRetryable(int status) {
		return classify(status) != StatusClass.FINAL;
	}

	/**
	 * Computes the wait before the next attempt. A server-provided {@code Retry-After}
	 * takes precedence (clamped to {@code maxBackoff}); otherwise an exponential backoff
	 * is used, also clamped.
	 * @param attempt the zero-based index of the retry about to be scheduled
	 * @param retryAfter the parsed {@code Retry-After} delay, or null when absent
	 * @return the delay to wait before retrying
	 */
	public Duration backoffFor(long attempt, Duration retryAfter) {
		if (retryAfter != null && !retryAfter.isNegative()) {
			return clamp(retryAfter);
		}
		// base * 2^attempt, guarding against overflow on large attempt counts.
		long multiplier = 1L << Math.min(attempt, 32);
		Duration exponential = baseBackoff.multipliedBy(multiplier);
		return clamp(exponential);
	}

	private Duration clamp(Duration d) {
		return (d.compareTo(maxBackoff) > 0) ? maxBackoff : d;
	}

	/**
	 * Parses a {@code Retry-After} header, which may be either a number of seconds or an
	 * HTTP date.
	 * @param headers the response headers
	 * @return the delay requested by the server, or null when absent or unparseable
	 */
	public static Duration parseRetryAfter(HttpHeaders headers) {
		if (headers == null) {
			return null;
		}
		String value = headers.getFirst(HttpHeaders.RETRY_AFTER);
		if (value == null || value.isBlank()) {
			return null;
		}
		value = value.trim();
		try {
			long seconds = Long.parseLong(value);
			return (seconds >= 0) ? Duration.ofSeconds(seconds) : null;
		}
		catch (NumberFormatException ignored) {
			// Not a plain seconds value: fall through to date parsing.
		}
		try {
			ZonedDateTime when = ZonedDateTime.parse(value, java.time.format.DateTimeFormatter.RFC_1123_DATE_TIME);
			Duration delay = Duration.between(ZonedDateTime.now(when.getZone()), when);
			return delay.isNegative() ? Duration.ZERO : delay;
		}
		catch (DateTimeParseException ignored) {
			return null;
		}
	}

	/**
	 * Retry classification of an HTTP status code.
	 */
	public enum StatusClass {

		/**
		 * Server-side transient failure (5xx family that is not a hard error).
		 */
		RETRYABLE_TRANSIENT,

		/**
		 * Explicit rate limiting (429).
		 */
		RETRYABLE_THROTTLE,

		/**
		 * Possible edge/WAF block surfacing as 401/403.
		 */
		RETRYABLE_BLOCKING,

		/**
		 * A definitive response that must be handed back to the scanner as-is.
		 */
		FINAL

	}

}

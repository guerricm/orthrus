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

import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.TimeoutException;
import java.util.function.Function;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import ch.nexsol.orthrusdast.config.OrthrusProperties;
import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.SecurityScheme;

/**
 * Reactive HTTP client wrapper around WebClient. Centralizes all HTTP interactions for
 * scanners: - Timeout management - Auth header injection - Response capture (status,
 * headers, body, timing) - Error handling (returns response info even on 4xx/5xx)
 *
 * <p>
 * Retry behaviour is delegated to {@link HttpRetryPolicy}: requests that hit a retryable
 * status (429/5xx, and 401/403 that may be edge blocks) are backed off and re-sent,
 * honouring {@code Retry-After}. When retries are exhausted the last real response is
 * handed back rather than a synthetic error, so scanners still see the actual status.
 */
@Component
public class ScanHttpClient {

	private static final Logger log = LoggerFactory.getLogger(ScanHttpClient.class);

	private static final int MAX_BODY_BYTES = 250_000;

	private final WebClient webClient;

	private final HttpRetryPolicy retryPolicy;

	private final Duration requestTimeout;

	public ScanHttpClient(WebClient webClient, OrthrusProperties properties) {
		this.webClient = webClient;
		this.retryPolicy = HttpRetryPolicy.from(properties.getHttp());
		this.requestTimeout = Duration.ofMillis(properties.getHttp().getRequestTimeoutMs());
	}

	/**
	 * Send a request based on an Operation and return the captured response.
	 * @param operation the operation
	 * @return the result
	 */
	public Mono<ScanHttpResponse> send(Operation operation) {
		return send(operation, Map.of(), null, true);
	}

	/**
	 * Send a request based on an Operation and return the captured response, optionally
	 * handling 429s.
	 * @param operation the operation
	 * @param retryTransientErrors whether to retry transient errors
	 * @return the result
	 */
	public Mono<ScanHttpResponse> send(Operation operation, boolean retryTransientErrors) {
		return send(operation, Map.of(), null, retryTransientErrors);
	}

	/**
	 * Send a request with extra headers (used by scanners to inject payloads).
	 * @param operation the operation
	 * @param extraHeaders extra headers
	 * @param bodyOverride body override
	 * @return the result
	 */
	public Mono<ScanHttpResponse> send(Operation operation, Map<String, String> extraHeaders, String bodyOverride) {
		return send(operation, extraHeaders, bodyOverride, true);
	}

	/**
	 * Send a request with extra headers, optionally handling 429s.
	 * @param operation the operation
	 * @param extraHeaders extra headers
	 * @param bodyOverride body override
	 * @param retryTransientErrors whether to retry transient errors
	 * @return the result
	 */
	public Mono<ScanHttpResponse> send(Operation operation, Map<String, String> extraHeaders, String bodyOverride,
			boolean retryTransientErrors) {
		String body = (bodyOverride != null) ? bodyOverride : operation.body();

		// Rebuilt on every attempt so the captured timing reflects only the last try, not
		// the accumulated retry backoff (which would otherwise inflate response times and
		// trip time-based injection heuristics). The timeout is applied per attempt, not
		// to
		// the whole retry chain, so legitimate retry backoff (including a server
		// Retry-After)
		// cannot trip it and discard the real response.
		Mono<ScanHttpResponse> attemptMono = Mono
			.defer(() -> singleAttempt(operation, extraHeaders, body, retryTransientErrors).timeout(requestTimeout));

		return attemptMono.retryWhen(buildRetry(retryTransientErrors))
			.onErrorResume((e) -> recoverFromError(operation, e));
	}

	private Mono<ScanHttpResponse> singleAttempt(Operation operation, Map<String, String> extraHeaders, String body,
			boolean retryTransientErrors) {
		long startTime = System.currentTimeMillis();
		HttpMethod method = operation.method();

		WebClient.RequestBodySpec requestSpec = webClient.method(method).uri(buildUri(operation)).headers((headers) -> {
			// Apply operation headers
			if (operation.headers() != null) {
				operation.headers().forEach((k, v) -> {
					if (v != null) {
						headers.set(k, v.replaceAll("[\\x00-\\x08\\x0A-\\x1F\\x7F]", "").trim());
					}
				});
			}
			// Apply auth scheme
			if (operation.authScheme() != null) {
				applyAuth(headers, operation.authScheme());
			}
			// Apply extra headers (scanner-injected)
			extraHeaders.forEach((k, v) -> {
				if (v != null) {
					headers.set(k, v.replaceAll("[\\x00-\\x08\\x0A-\\x1F\\x7F]", "").trim());
				}
			});
		});

		Function<ClientResponse, Mono<ScanHttpResponse>> responseHandler = (
				clientResponse) -> clientResponse.bodyToMono(String.class).defaultIfEmpty("").map((responseBody) -> {
					String finalBody = responseBody;
					if (finalBody.length() > MAX_BODY_BYTES) {
						finalBody = finalBody.substring(0, MAX_BODY_BYTES) + "\n...[TRUNCATED BY ORTHRUS DAST]...";
					}
					return new ScanHttpResponse(clientResponse.statusCode(), clientResponse.headers().asHttpHeaders(),
							finalBody, System.currentTimeMillis() - startTime);
				}).flatMap((response) -> {
					int status = response.statusCode().value();
					if (retryTransientErrors && retryPolicy.isRetryable(status)) {
						Duration retryAfter = HttpRetryPolicy.parseRetryAfter(response.headers());
						return Mono.error(new RetryableResponseException(status, response, retryAfter));
					}
					return Mono.just(response);
				});

		if (body != null && !body.isEmpty()) {
			String cType = (operation.headers() != null) ? operation.headers().get("Content-Type") : null;
			if (cType == null) {
				cType = extraHeaders.get("Content-Type");
			}
			if (cType != null) {
				requestSpec.contentType(MediaType.parseMediaType(cType));
			}
			return requestSpec.bodyValue(body).exchangeToMono(responseHandler);
		}
		return requestSpec.exchangeToMono(responseHandler);
	}

	private Retry buildRetry(boolean retryTransientErrors) {
		return Retry.from((companion) -> companion.flatMap((signal) -> {
			Throwable failure = signal.failure();
			boolean retryable = failure instanceof RetryableResponseException
					|| (retryTransientErrors && isTransientNetworkError(failure));
			// Ambiguous statuses (401/403 blocks, 500) get a smaller budget than clearly
			// transient failures; network errors use the transient budget.
			int applicableMax = (failure instanceof RetryableResponseException rre)
					? retryPolicy.maxRetriesForStatus(rre.status()) : retryPolicy.maxRetries();
			if (!retryable || signal.totalRetries() >= applicableMax) {
				// Exhausted, or not a retryable failure: propagate so onErrorResume can
				// surface the real response (or a synthetic error for network failures).
				return Mono.error(failure);
			}
			Duration retryAfter = (failure instanceof RetryableResponseException rre) ? rre.retryAfter() : null;
			Duration backoff = retryPolicy.backoffFor(signal.totalRetries(), retryAfter);
			return Mono.delay(backoff).thenReturn(signal.totalRetries());
		}));
	}

	private Mono<ScanHttpResponse> recoverFromError(Operation operation, Throwable e) {
		// A retryable status that survived all attempts: hand back the real response so
		// scanners judge the actual status rather than a fabricated 503.
		if (e instanceof RetryableResponseException rre) {
			return Mono.just(rre.response());
		}

		String logUrl = operation.url();
		if (logUrl != null && logUrl.length() > 100) {
			logUrl = logUrl.substring(0, 100) + "...[TRUNCATED]";
		}

		String errorMsg = e.getMessage();
		if (e instanceof TimeoutException) {
			errorMsg = "Request exceeded the " + requestTimeout.toMillis() + "ms budget";
		}

		log.warn("HTTP request failed for {} {}: {}", operation.method().name(), logUrl, errorMsg);
		return Mono.just(new ScanHttpResponse(HttpStatus.SERVICE_UNAVAILABLE, new HttpHeaders(), "Error: " + errorMsg,
				requestTimeout.toMillis()));
	}

	/**
	 * Send a raw request (no Operation) — used for well-known path discovery.
	 * @param url the url
	 * @return the result
	 */
	public Mono<ScanHttpResponse> sendGet(String url) {
		return send(Operation.simple(url, HttpMethod.GET));
	}

	/**
	 * Send a raw request with custom method.
	 * @param url the url
	 * @param method the method
	 * @param headers the headers
	 * @param body the body
	 * @return the result
	 */
	public Mono<ScanHttpResponse> sendRaw(String url, HttpMethod method, Map<String, String> headers, String body) {
		Operation op = Operation.withHeaders(url, method, headers, body);
		return send(op);
	}

	/**
	 * Send the same request multiple times rapidly (for rate-limiting tests).
	 * @param operation the operation
	 * @param count the count
	 * @return the result
	 */
	public Mono<ScanHttpResponse> sendNTimes(Operation operation, int count) {
		return Mono.defer(() -> send(operation)).repeat(count - 1).last();
	}

	private URI buildUri(Operation operation) {
		UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(operation.url());
		if (operation.queryParams() != null) {
			operation.queryParams().forEach(builder::queryParam);
		}
		return builder.build().encode().toUri();
	}

	private void applyAuth(HttpHeaders headers, SecurityScheme scheme) {
		if (scheme.paramLocation() == SecurityScheme.ParamLocation.HEADER) {
			String headerName = (scheme.headerName() != null) ? scheme.headerName() : "Authorization";
			String headerValue = scheme.toAuthorizationHeaderValue();
			if (headerValue != null) {
				headerValue = headerValue.replaceAll("[\\x00-\\x08\\x0A-\\x1F\\x7F]", "").trim();
				headers.set(headerName, headerValue);
			}
		}
		// Query param auth is handled in buildUri
	}

	private boolean isTransientNetworkError(Throwable e) {
		if (e == null) {
			return false;
		}
		if (e instanceof IOException || e instanceof TimeoutException
				|| e.getClass().getName().contains("TimeoutException")
				|| e.getClass().getName().contains("PrematureCloseException")) {
			return true;
		}
		Throwable cause = e.getCause();
		if (cause != null && cause != e) {
			return isTransientNetworkError(cause);
		}
		return false;
	}

	/**
	 * Signals that a fully-read response carried a retryable status. It transports the
	 * captured {@link ScanHttpResponse} so that, once retries are exhausted, the real
	 * response can be surfaced to scanners instead of a synthetic error.
	 */
	private static final class RetryableResponseException extends RuntimeException {

		private final int status;

		private final transient ScanHttpResponse response;

		private final transient Duration retryAfter;

		RetryableResponseException(int status, ScanHttpResponse response, Duration retryAfter) {
			super("Retryable HTTP status " + status);
			this.status = status;
			this.response = response;
			this.retryAfter = retryAfter;
		}

		int status() {
			return status;
		}

		ScanHttpResponse response() {
			return response;
		}

		Duration retryAfter() {
			return retryAfter;
		}

	}

}

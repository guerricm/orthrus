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

import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.SecurityScheme;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.Map;

/**
 * Reactive HTTP client wrapper around WebClient. Centralizes all HTTP interactions for
 * scanners: - Timeout management - Auth header injection - Response capture (status,
 * headers, body, timing) - Error handling (returns response info even on 4xx/5xx)
 */
@Component
public class ScanHttpClient {

	private static final Logger log = LoggerFactory.getLogger(ScanHttpClient.class);

	private final WebClient webClient;

	public ScanHttpClient(WebClient webClient) {
		this.webClient = webClient;
	}

	/**
	 * Send a request based on an Operation and return the captured response.
	 */
	public Mono<ScanHttpResponse> send(Operation operation) {
		return send(operation, Map.of(), null, true);
	}

	/**
	 * Send a request based on an Operation and return the captured response, optionally
	 * handling 429s.
	 */
	public Mono<ScanHttpResponse> send(Operation operation, boolean retryTransientErrors) {
		return send(operation, Map.of(), null, retryTransientErrors);
	}

	/**
	 * Send a request with extra headers (used by scanners to inject payloads).
	 */
	public Mono<ScanHttpResponse> send(Operation operation, Map<String, String> extraHeaders, String bodyOverride) {
		return send(operation, extraHeaders, bodyOverride, true);
	}

	/**
	 * Send a request with extra headers, optionally handling 429s.
	 */
	public Mono<ScanHttpResponse> send(Operation operation, Map<String, String> extraHeaders, String bodyOverride,
			boolean retryTransientErrors) {
		long startTime = System.currentTimeMillis();

		HttpMethod method = HttpMethod.valueOf(operation.method().toUpperCase());

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

		String body = bodyOverride != null ? bodyOverride : operation.body();

		java.util.function.Function<ClientResponse, Mono<ScanHttpResponse>> responseHandler = (clientResponse) -> {
			int status = clientResponse.statusCode().value();
			if (retryTransientErrors && (status == 429 || status == 502 || status == 503 || status == 504)) {
				return Mono.error(new TransientHttpException("Transient HTTP error (" + status + ")"));
			}
			return clientResponse.bodyToMono(String.class).defaultIfEmpty("").map((responseBody) -> {
				String finalBody = responseBody;
				if (finalBody.length() > 250_000) {
					finalBody = finalBody.substring(0, 250_000) + "\n...[TRUNCATED BY ORTHRUS DAST]...";
				}
				return new ScanHttpResponse(clientResponse.statusCode(), clientResponse.headers().asHttpHeaders(),
						finalBody, System.currentTimeMillis() - startTime);
			});
		};

		Mono<ScanHttpResponse> resultMono;
		if (body != null && !body.isEmpty()) {
			String cType = operation.headers() != null ? operation.headers().get("Content-Type") : null;
			if (cType == null)
				cType = extraHeaders.get("Content-Type");
			if (cType != null) {
				requestSpec.contentType(org.springframework.http.MediaType.parseMediaType(cType));
			}
			resultMono = requestSpec.bodyValue(body).exchangeToMono(responseHandler);
		}
		else {
			resultMono = requestSpec.exchangeToMono(responseHandler);
		}

		return resultMono.retryWhen(reactor.util.retry.Retry.backoff(4, Duration.ofSeconds(1)) // Retries
																								// 4
																								// times
																								// with
																								// exp
																								// backoff
																								// (1s,
																								// 2s,
																								// 4s,
																								// 8s)
			.filter((e) -> e instanceof TransientHttpException || (retryTransientErrors && isTransientNetworkError(e)))
			.onRetryExhaustedThrow((retryBackoffSpec, retrySignal) -> retrySignal.failure()))
			.timeout(Duration.ofSeconds(30))
			.onErrorResume((e) -> {
				String logUrl = operation.url();
				if (logUrl != null && logUrl.length() > 100) {
					logUrl = logUrl.substring(0, 100) + "...[TRUNCATED]";
				}

				String errorMsg = e.getMessage();
				if (e instanceof java.util.concurrent.TimeoutException) {
					errorMsg = "Request timed out after 15 seconds";
				}

				log.warn("HTTP request failed for {} {}: {}", operation.method(), logUrl, errorMsg);
				return Mono.just(new ScanHttpResponse(org.springframework.http.HttpStatus.SERVICE_UNAVAILABLE,
						new HttpHeaders(), "Error: " + errorMsg, System.currentTimeMillis() - startTime));
			});
	}

	/**
	 * Send a raw request (no Operation) — used for well-known path discovery.
	 */
	public Mono<ScanHttpResponse> sendGet(String url) {
		return send(Operation.simple(url, "GET"));
	}

	/**
	 * Send a raw request with custom method.
	 */
	public Mono<ScanHttpResponse> sendRaw(String url, String method, Map<String, String> headers, String body) {
		Operation op = Operation.withHeaders(url, method, headers, body);
		return send(op);
	}

	/**
	 * Send the same request multiple times rapidly (for rate-limiting tests).
	 */
	public Mono<ScanHttpResponse> sendNTimes(Operation operation, int count) {
		return Mono.defer(() -> send(operation)).repeat(count - 1).last();
	}

	private java.net.URI buildUri(Operation operation) {
		org.springframework.web.util.UriComponentsBuilder builder = org.springframework.web.util.UriComponentsBuilder
			.fromUriString(operation.url());
		if (operation.queryParams() != null) {
			operation.queryParams().forEach(builder::queryParam);
		}
		return builder.build().encode().toUri();
	}

	private void applyAuth(HttpHeaders headers, SecurityScheme scheme) {
		if (scheme.paramLocation() == SecurityScheme.ParamLocation.HEADER) {
			String headerName = scheme.headerName() != null ? scheme.headerName() : "Authorization";
			String headerValue = scheme.toAuthorizationHeaderValue();
			if (headerValue != null) {
				headerValue = headerValue.replaceAll("[\\x00-\\x08\\x0A-\\x1F\\x7F]", "").trim();
				headers.set(headerName, headerValue);
			}
		}
		// Query param auth is handled in buildUri
	}

	private boolean isTransientNetworkError(Throwable e) {
		if (e == null)
			return false;
		if (e instanceof java.io.IOException || e instanceof java.util.concurrent.TimeoutException
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

	private static class TransientHttpException extends RuntimeException {

		public TransientHttpException(String message) {
			super(message);
		}

	}

}

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

package ch.nexsol.orthrusdast.scanner;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import ch.nexsol.orthrusdast.http.ScanHttpClient;
import ch.nexsol.orthrusdast.http.ScanHttpResponse;
import ch.nexsol.orthrusdast.model.Operation;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The scanner draws requests until a 429 appears. A burst that never hits 429 means
 * "missing rate limiting" only when the server does not advertise a rate limiter in its
 * headers; when it does (Spring Cloud Gateway, IETF RateLimit, a Retry-After), the budget
 * was simply not exhausted and reporting it missing is a false positive.
 */
class RateLimitingScannerTest {

	private final ScanHttpClient httpClient = Mockito.mock(ScanHttpClient.class);

	private final RateLimitingScanner scanner = new RateLimitingScanner(this.httpClient);

	@Test
	void reportsMissingRateLimitingWhenNo429AndNoRateLimitHeaders() {
		stubEveryRequest(new ScanHttpResponse(HttpStatus.NOT_FOUND, new HttpHeaders(), "{}", 1L));

		StepVerifier.create(this.scanner.scan(stateChangingOperation()))
			.assertNext((vuln) -> assertThat(vuln.name()).isEqualTo("Missing Rate Limiting"))
			.verifyComplete();
	}

	@Test
	void doesNotReportMissingRateLimitingWhenTheResponseAdvertisesALimiter() {
		HttpHeaders headers = new HttpHeaders();
		headers.add("X-Ratelimit-Burst-Capacity", "150");
		headers.add("X-Ratelimit-Remaining", "83");
		headers.add("X-Ratelimit-Replenish-Rate", "100");
		stubEveryRequest(new ScanHttpResponse(HttpStatus.NOT_FOUND, headers, "{}", 1L));

		StepVerifier.create(this.scanner.scan(stateChangingOperation())).verifyComplete();
	}

	private void stubEveryRequest(ScanHttpResponse response) {
		Mockito.when(this.httpClient.send(ArgumentMatchers.any(), ArgumentMatchers.anyBoolean()))
			.thenReturn(Mono.just(response));
	}

	private static Operation stateChangingOperation() {
		return new Operation("http://api.test/rooms/1/participants/1/hug-token", HttpMethod.GET, Map.of(), Map.of(),
				null, List.of(), List.of(), null);
	}

}

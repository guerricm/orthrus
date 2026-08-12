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

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;

import ch.nexsol.orthrusdast.http.HttpRetryPolicy.StatusClass;

import static org.assertj.core.api.Assertions.assertThat;

class HttpRetryPolicyTest {

	private final HttpRetryPolicy policy = new HttpRetryPolicy(4, 1, Duration.ofSeconds(1), Duration.ofSeconds(30));

	@Test
	void classifiesRetryableAndFinalStatuses() {
		assertThat(HttpRetryPolicy.classify(429)).isEqualTo(StatusClass.RETRYABLE_THROTTLE);
		assertThat(HttpRetryPolicy.classify(503)).isEqualTo(StatusClass.RETRYABLE_TRANSIENT);
		assertThat(HttpRetryPolicy.classify(500)).isEqualTo(StatusClass.RETRYABLE_TRANSIENT);
		assertThat(HttpRetryPolicy.classify(401)).isEqualTo(StatusClass.RETRYABLE_BLOCKING);
		assertThat(HttpRetryPolicy.classify(403)).isEqualTo(StatusClass.RETRYABLE_BLOCKING);

		assertThat(HttpRetryPolicy.classify(200)).isEqualTo(StatusClass.FINAL);
		assertThat(HttpRetryPolicy.classify(404)).isEqualTo(StatusClass.FINAL);
		assertThat(HttpRetryPolicy.classify(422)).isEqualTo(StatusClass.FINAL);
	}

	@Test
	void ambiguousStatusesGetSmallerBudget() {
		// Clearly transient failures get the full budget.
		assertThat(policy.maxRetriesForStatus(429)).isEqualTo(4);
		assertThat(policy.maxRetriesForStatus(503)).isEqualTo(4);
		assertThat(policy.maxRetriesForStatus(502)).isEqualTo(4);

		// Ambiguous statuses (auth walls, error-based-injection 500s) get the small
		// budget.
		assertThat(policy.maxRetriesForStatus(401)).isEqualTo(1);
		assertThat(policy.maxRetriesForStatus(403)).isEqualTo(1);
		assertThat(policy.maxRetriesForStatus(500)).isEqualTo(1);
	}

	@Test
	void exponentialBackoffGrowsAndIsCapped() {
		assertThat(policy.backoffFor(0, null)).isEqualTo(Duration.ofSeconds(1));
		assertThat(policy.backoffFor(1, null)).isEqualTo(Duration.ofSeconds(2));
		assertThat(policy.backoffFor(2, null)).isEqualTo(Duration.ofSeconds(4));
		// 2^10 seconds would be far beyond the 30s cap.
		assertThat(policy.backoffFor(10, null)).isEqualTo(Duration.ofSeconds(30));
	}

	@Test
	void retryAfterTakesPrecedenceAndIsClamped() {
		assertThat(policy.backoffFor(0, Duration.ofSeconds(5))).isEqualTo(Duration.ofSeconds(5));
		assertThat(policy.backoffFor(0, Duration.ofSeconds(120))).isEqualTo(Duration.ofSeconds(30));
	}

	@Test
	void parsesRetryAfterAsSeconds() {
		HttpHeaders headers = new HttpHeaders();
		headers.set(HttpHeaders.RETRY_AFTER, "7");
		assertThat(HttpRetryPolicy.parseRetryAfter(headers)).isEqualTo(Duration.ofSeconds(7));
	}

	@Test
	void returnsNullWhenRetryAfterAbsentOrUnparseable() {
		assertThat(HttpRetryPolicy.parseRetryAfter(new HttpHeaders())).isNull();

		HttpHeaders garbage = new HttpHeaders();
		garbage.set(HttpHeaders.RETRY_AFTER, "soon");
		assertThat(HttpRetryPolicy.parseRetryAfter(garbage)).isNull();
	}

}

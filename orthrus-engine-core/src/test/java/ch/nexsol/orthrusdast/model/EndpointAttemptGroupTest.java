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

import java.util.List;

import org.junit.jupiter.api.Test;

import ch.nexsol.orthrus.protocol.node.AttemptStatus;
import ch.nexsol.orthrus.protocol.node.ScanAttempt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;

class EndpointAttemptGroupTest {

	@Test
	void attemptsAreGroupedPerEndpointInOrderOfFirstAppearance() {
		List<EndpointAttemptGroup> groups = EndpointAttemptGroup.groupByEndpoint(
				List.of(attempt("GET", "/b", AttemptStatus.PASSED), attempt("GET", "/a", AttemptStatus.PASSED),
						attempt("GET", "/b", AttemptStatus.FAILED), attempt("POST", "/b", AttemptStatus.PASSED)));

		assertThat(groups).extracting(EndpointAttemptGroup::endpoint, (g) -> g.attempts().size())
			.containsExactly(tuple("GET /b", 2), tuple("GET /a", 1), tuple("POST /b", 1));
	}

	@Test
	void eachStatusIsCountedSeparately() {
		List<EndpointAttemptGroup> groups = EndpointAttemptGroup
			.groupByEndpoint(List.of(attempt("GET", "/a", AttemptStatus.PASSED),
					attempt("GET", "/a", AttemptStatus.FAILED), attempt("GET", "/a", AttemptStatus.AUTH_ERROR),
					attempt("GET", "/a", AttemptStatus.FORBIDDEN), attempt("GET", "/a", AttemptStatus.FORBIDDEN),
					attempt("GET", "/a", AttemptStatus.ERROR), attempt("GET", "/a", AttemptStatus.NOT_RUN)));

		assertThat(groups).singleElement()
			.satisfies((g) -> assertThat(
					List.of(g.passed(), g.failed(), g.authError(), g.forbidden(), g.error(), g.notRun()))
				.containsExactly(1L, 1L, 1L, 2L, 1L, 1L));
	}

	@Test
	void noAttemptsGiveNoGroup() {
		assertThat(EndpointAttemptGroup.groupByEndpoint(List.of())).isEmpty();
	}

	private static ScanAttempt attempt(String method, String url, AttemptStatus status) {
		return new ScanAttempt("s", "Scanner", method, url, status, List.of());
	}

}

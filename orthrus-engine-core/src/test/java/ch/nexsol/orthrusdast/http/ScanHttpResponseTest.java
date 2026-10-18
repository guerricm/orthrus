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

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A response the client produced because the target never answered carries the client's
 * own error message, which often quotes the payload (an injected host name, a URL). It
 * must never count as the target reflecting that payload.
 */
class ScanHttpResponseTest {

	@Test
	void aClientErrorNeverMatchesItsOwnMessage() {
		ScanHttpResponse error = ScanHttpResponse.clientError("Failed to resolve 'abc.oast.invalid'", 10);

		assertThat(error.clientError()).isTrue();
		assertThat(error.statusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
		assertThat(error.body()).isEmpty();
		assertThat(error.clientMessage()).contains("abc.oast.invalid");
		assertThat(error.bodyContainsExact("abc.oast.invalid")).isFalse();
		assertThat(error.bodyContains("ABC.OAST.INVALID")).isFalse();
	}

	@Test
	void aRealResponseStillMatches() {
		ScanHttpResponse real = new ScanHttpResponse(HttpStatus.OK, new HttpHeaders(), "link to abc.oast.invalid", 5);

		assertThat(real.clientError()).isFalse();
		assertThat(real.clientMessage()).isNull();
		assertThat(real.bodyContainsExact("abc.oast.invalid")).isTrue();
	}

}

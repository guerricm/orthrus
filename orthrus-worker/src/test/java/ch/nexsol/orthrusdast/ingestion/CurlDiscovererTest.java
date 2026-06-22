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

package ch.nexsol.orthrusdast.ingestion;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import reactor.test.StepVerifier;

import static org.assertj.core.api.Assertions.assertThat;

class CurlDiscovererTest {

	@Test
	void testGetId() {
		CurlDiscoverer discoverer = new CurlDiscoverer();
		assertThat(discoverer.getId()).isEqualTo("curl");
	}

	@Test
	void testDiscoverSimpleUrl() {
		CurlDiscoverer discoverer = new CurlDiscoverer();
		StepVerifier.create(discoverer.discover("http://example.com/api", null)).assertNext((ops) -> {
			assertThat(ops).hasSize(1);
			assertThat(ops.get(0).url()).isEqualTo("http://example.com/api");
			assertThat(ops.get(0).method()).isEqualTo(HttpMethod.GET);
		}).verifyComplete();
	}

}

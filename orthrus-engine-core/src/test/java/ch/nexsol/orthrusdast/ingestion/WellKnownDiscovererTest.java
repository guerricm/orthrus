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
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import ch.nexsol.orthrusdast.http.ScanHttpClient;
import ch.nexsol.orthrusdast.http.ScanHttpResponse;

import static org.assertj.core.api.Assertions.assertThat;

class WellKnownDiscovererTest {

	@Test
	void testGetId() {
		WellKnownDiscoverer discoverer = new WellKnownDiscoverer(Mockito.mock(ScanHttpClient.class));
		assertThat(discoverer.getId()).isEqualTo("well-known");
	}

	@Test
	void testDiscoverInvalidUrl() {
		ScanHttpClient mockClient = Mockito.mock(ScanHttpClient.class);
		Mockito.when(mockClient.send(ArgumentMatchers.any()))
			.thenReturn(Mono.just(new ScanHttpResponse(HttpStatus.NOT_FOUND, new HttpHeaders(), "", 0L)));

		WellKnownDiscoverer discoverer = new WellKnownDiscoverer(mockClient);
		StepVerifier.create(discoverer.discover("http://invalid-url:9999", null))
			.assertNext((ops) -> assertThat(ops).isEmpty())
			.verifyComplete();
	}

}

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
import reactor.test.StepVerifier;

import ch.nexsol.orthrusdast.config.OrthrusProperties;

import static org.assertj.core.api.Assertions.assertThat;

public class BlackboxDiscovererTest {

	@Test
	public void testBlackboxCrawler() {
		BlackboxDiscoverer discoverer = new BlackboxDiscoverer(new OrthrusProperties());
		// Since it's a component now, we would normally use @SpringBootTest or set
		// properties manually
		// For a simple test, we just verify it doesn't crash on a bad URL

		StepVerifier.create(discoverer.discover("http://invalid-local-domain-that-does-not-exist.test", null))
			.assertNext((operations) -> assertThat(operations.isEmpty() || operations.size() == 1).isTrue())
			.verifyComplete();
	}

}

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
import tools.jackson.databind.ObjectMapper;

import static org.assertj.core.api.Assertions.assertThat;

class GatewayExclusionsTest {

	@Test
	void aPlainPathExcludesItselfAndEverythingBelowButNotLookalikes() {
		GatewayExclusions exclusions = new GatewayExclusions(List.of(), List.of("/admin"));

		assertThat(exclusions.excludesPath("/admin")).isTrue();
		assertThat(exclusions.excludesPath("/admin/users/1")).isTrue();
		assertThat(exclusions.excludesPath("/administrators")).isFalse();
		assertThat(exclusions.excludesPath("/api/admin")).isFalse();
	}

	@Test
	void antPatternsAreMatched() {
		GatewayExclusions exclusions = new GatewayExclusions(List.of(), List.of("/api/*/internal/**"));

		assertThat(exclusions.excludesPath("/api/v1/internal/metrics")).isTrue();
		assertThat(exclusions.excludesPath("/api/v1/public")).isFalse();
	}

	@Test
	void routeIdsMatchExactly() {
		GatewayExclusions exclusions = new GatewayExclusions(List.of("admin-route"), List.of());

		assertThat(exclusions.excludesRoute("admin-route")).isTrue();
		assertThat(exclusions.excludesRoute("admin")).isFalse();
		assertThat(exclusions.excludesRoute(null)).isFalse();
	}

	@Test
	void noExclusionsExcludesNothing() {
		GatewayExclusions none = new GatewayExclusions(null, null);

		assertThat(none.isEmpty()).isTrue();
		assertThat(none.excludesPath("/anything")).isFalse();
	}

	@Test
	void aConfigurationSavedBeforeExclusionsExistedReadsAsNone() {
		ObjectMapper mapper = new ObjectMapper();
		String saved = mapper.writeValueAsString(ScanConfiguration.defaults())
			.replace(",\"gatewayExclusions\":null", "");
		assertThat(saved).doesNotContain("gatewayExclusions");

		ScanConfiguration legacy = mapper.readValue(saved, ScanConfiguration.class);

		assertThat(legacy.gatewayExclusions()).isNull();
		assertThat(legacy.gatewayExclusionsOrNone().isEmpty()).isTrue();
	}

}

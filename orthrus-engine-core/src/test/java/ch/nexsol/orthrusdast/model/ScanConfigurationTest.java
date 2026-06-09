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

import org.junit.jupiter.api.Test;
import java.util.List;
import static org.assertj.core.api.Assertions.assertThat;

class ScanConfigurationTest {

	@Test
	void testDefaults() {
		ScanConfiguration config = ScanConfiguration.defaults();

		assertThat(config).isNotNull();
		assertThat(config.includeScanners()).isEmpty();
		assertThat(config.excludeScanners()).isEmpty();
		assertThat(config.concurrency()).isEqualTo(10);
		assertThat(config.httpConnectTimeoutMs()).isEqualTo(5000);
		assertThat(config.httpReadTimeoutMs()).isEqualTo(10000);
		assertThat(config.ignoreSslErrors()).isFalse();
		assertThat(config.reportFormat()).isEqualTo("json");
		assertThat(config.authScheme()).isNull();
		assertThat(config.secondaryAuthScheme()).isNull();
		assertThat(config.language()).isEqualTo("en");
		assertThat(config.includePassed()).isFalse();
		assertThat(config.gatewayType()).isEqualTo(GatewayType.AUTO);
		assertThat(config.appUrl()).isNull();
		assertThat(config.k8sToken()).isNull();
	}

	@Test
	void testShouldRunScanner() {
		ScanConfiguration configWithIncludes = new ScanConfiguration(List.of("sql-injection", "xss"), List.of(), 10,
				5000, 10000, false, "json", null, null, "en", false, GatewayType.AUTO, null, null, null, null);

		assertThat(configWithIncludes.shouldRunScanner("sql-injection")).isTrue();
		assertThat(configWithIncludes.shouldRunScanner("xss")).isTrue();
		assertThat(configWithIncludes.shouldRunScanner("csrf")).isFalse();

		ScanConfiguration configWithExcludes = new ScanConfiguration(List.of(), List.of("csrf", "ssti"), 10, 5000,
				10000, false, "json", null, null, "en", false, GatewayType.AUTO, null, null, null, null);

		assertThat(configWithExcludes.shouldRunScanner("sql-injection")).isTrue();
		assertThat(configWithExcludes.shouldRunScanner("csrf")).isFalse();
		assertThat(configWithExcludes.shouldRunScanner("ssti")).isFalse();

		ScanConfiguration configWithBoth = new ScanConfiguration(List.of("sql-injection", "csrf"), List.of("csrf"), 10,
				5000, 10000, false, "json", null, null, "en", false, GatewayType.AUTO, null, null, null, null);

		// Excludes take precedence over includes
		assertThat(configWithBoth.shouldRunScanner("csrf")).isFalse();
		assertThat(configWithBoth.shouldRunScanner("sql-injection")).isTrue();
	}

}

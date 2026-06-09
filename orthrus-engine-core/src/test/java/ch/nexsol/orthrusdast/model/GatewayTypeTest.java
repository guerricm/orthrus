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
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class GatewayTypeTest {

	@Test
	void testFromString_ValidInputs() {
		assertThat(GatewayType.fromString("traefik")).isEqualTo(GatewayType.TRAEFIK);
		assertThat(GatewayType.fromString("TRAEFIK")).isEqualTo(GatewayType.TRAEFIK);
		assertThat(GatewayType.fromString("spring-cloud-gateway")).isEqualTo(GatewayType.SPRING_CLOUD_GATEWAY);
		assertThat(GatewayType.fromString("kong")).isEqualTo(GatewayType.KONG);
		assertThat(GatewayType.fromString("haproxy")).isEqualTo(GatewayType.HAPROXY);
		assertThat(GatewayType.fromString("k8s")).isEqualTo(GatewayType.K8S);
		assertThat(GatewayType.fromString("auto")).isEqualTo(GatewayType.AUTO);
	}

	@Test
	void testFromString_EmptyOrNullReturnsAuto() {
		assertThat(GatewayType.fromString(null)).isEqualTo(GatewayType.AUTO);
		assertThat(GatewayType.fromString("")).isEqualTo(GatewayType.AUTO);
		assertThat(GatewayType.fromString("   ")).isEqualTo(GatewayType.AUTO);
	}

	@Test
	void testFromString_InvalidThrowsException() {
		assertThatThrownBy(() -> GatewayType.fromString("nginx")).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> GatewayType.fromString("unknown")).isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void testGetValue() {
		assertThat(GatewayType.TRAEFIK.getValue()).isEqualTo("traefik");
		assertThat(GatewayType.K8S.getValue()).isEqualTo("k8s");
	}

}

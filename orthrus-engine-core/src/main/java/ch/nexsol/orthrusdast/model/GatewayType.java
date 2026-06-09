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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

public enum GatewayType {

	AUTO("auto"), TRAEFIK("traefik"), SPRING_CLOUD_GATEWAY("spring-cloud-gateway"), KONG("kong"), HAPROXY("haproxy"),
	K8S("k8s");

	private final String value;

	GatewayType(String value) {
		this.value = value;
	}

	@JsonValue
	public String getValue() {
		return value;
	}

	@JsonCreator
	public static GatewayType fromString(String value) {
		if (value == null || value.isBlank()) {
			return AUTO;
		}
		for (GatewayType type : GatewayType.values()) {
			if (type.value.equalsIgnoreCase(value.trim()) || type.name().equalsIgnoreCase(value.trim())) {
				return type;
			}
		}
		throw new IllegalArgumentException("Unknown GatewayType: " + value);
	}

}

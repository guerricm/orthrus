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

package ch.nexsol.orthrusdast.config;

import java.util.ArrayList;
import java.util.List;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

/**
 * Refuses to start a production deployment that still carries the shipped credentials.
 * Outside the production profile the same findings are logged as warnings.
 */
@Component
public class DefaultSecretsCheck {

	private static final Logger log = LoggerFactory.getLogger(DefaultSecretsCheck.class);

	private static final String DEFAULT_INTERNAL_TOKEN = "change-me-in-production";

	private static final String DEFAULT_ADMIN_PASSWORD = "superadmin";

	private static final String PRODUCTION_PROFILE = "prod";

	private final OrthrusProperties properties;

	private final Environment environment;

	@Value("${orthrus.security.admin.password:}")
	private String adminPassword;

	public DefaultSecretsCheck(OrthrusProperties properties, Environment environment) {
		this.properties = properties;
		this.environment = environment;
	}

	@PostConstruct
	void verify() {
		List<String> findings = new ArrayList<>();

		if (DEFAULT_INTERNAL_TOKEN.equals(this.properties.getMaster().getInternalToken())) {
			findings.add("orthrus.master.internal-token is still the shipped default — "
					+ "anyone could register a rogue worker or post scan results");
		}
		if (DEFAULT_ADMIN_PASSWORD.equals(this.adminPassword)) {
			findings.add("orthrus.security.admin.password is still the shipped default — "
					+ "set ADMIN_PASSWORD to a real secret");
		}

		if (findings.isEmpty()) {
			return;
		}

		if (isProduction()) {
			throw new IllegalStateException(
					"Refusing to start with default credentials: " + String.join("; ", findings));
		}
		findings.forEach((finding) -> log.warn("INSECURE DEFAULT: {}", finding));
	}

	private boolean isProduction() {
		for (String profile : this.environment.getActiveProfiles()) {
			if (PRODUCTION_PROFILE.equalsIgnoreCase(profile)) {
				return true;
			}
		}
		return false;
	}

}

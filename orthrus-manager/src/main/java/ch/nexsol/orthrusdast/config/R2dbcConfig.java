// src/main/java/ch/nexsol/orthrusdast/config/R2dbcConfig.java
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

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.ReactiveAuditorAware;
import org.springframework.data.r2dbc.config.EnableR2dbcAuditing;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

/**
 * R2DBC Configuration for Auditing.
 */
@Configuration
@EnableR2dbcAuditing(auditorAwareRef = "auditorAware")
public class R2dbcConfig {

	/**
	 * Extracts the username from the security context to be used for auditing.
	 * @return a {@link ReactiveAuditorAware} instance
	 */
	@Bean
	public ReactiveAuditorAware<String> auditorAware() {
		return () -> ReactiveSecurityContextHolder.getContext()
			.map(SecurityContext::getAuthentication)
			.filter(Authentication::isAuthenticated)
			.map((auth) -> {
				if (auth instanceof JwtAuthenticationToken jwtToken) {
					Jwt jwt = jwtToken.getToken();
					if (jwt.hasClaim("preferred_username")) {
						return jwt.getClaimAsString("preferred_username");
					}
				}
				else if (auth instanceof OAuth2AuthenticationToken oauthToken) {
					OAuth2User oauth2User = oauthToken.getPrincipal();
					if (oauth2User.getAttributes().containsKey("preferred_username")) {
						return (String) oauth2User.getAttributes().get("preferred_username");
					}
				}
				return auth.getName();
			})
			.defaultIfEmpty("system");
	}

}

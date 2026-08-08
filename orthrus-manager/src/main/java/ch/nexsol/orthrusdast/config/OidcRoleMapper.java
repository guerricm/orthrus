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
import java.util.Base64;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.userinfo.DefaultReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

/**
 * Mapper for OAuth2/OIDC roles from Keycloak to Spring Security roles.
 */
@Configuration
public class OidcRoleMapper {

	private final ObjectMapper objectMapper = new ObjectMapper();

	/**
	 * Custom OIDC user service to extract roles from Keycloak OIDC tokens.
	 * @return the reactive OIDC user service
	 */
	@Bean
	public ReactiveOAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
		final OidcReactiveOAuth2UserService delegate = new OidcReactiveOAuth2UserService();

		return (userRequest) -> delegate.loadUser(userRequest).map((oidcUser) -> {
			Collection<GrantedAuthority> mappedAuthorities = new ArrayList<>(oidcUser.getAuthorities());

			// 1. Try to extract from ID Token / UserInfo
			boolean mapped = extractKeycloakRoles(oidcUser.getAttributes(), mappedAuthorities);

			// 2. If not found, Keycloak often puts roles in the Access Token. Let's parse
			// it.
			Map<String, Object> accessTokenAttrs = null;
			if (!mapped) {
				accessTokenAttrs = extractRolesFromAccessToken(userRequest.getAccessToken().getTokenValue(),
						mappedAuthorities);
			}

			final Map<String, Object> finalAccessTokenAttrs = accessTokenAttrs;
			return new DefaultOidcUser(mappedAuthorities, oidcUser.getIdToken(), oidcUser.getUserInfo()) {
				@Override
				public String getName() {
					return displayName(getAttributes(), finalAccessTokenAttrs, super::getName);
				}

				@Override
				public Map<String, Object> getAttributes() {
					return mergeAttributes(super.getAttributes(), finalAccessTokenAttrs);
				}
			};
		});
	}

	/**
	 * Custom OAuth2 user service to extract roles from Keycloak UserInfo when openid
	 * scope is missing.
	 * @return the reactive OAuth2 user service
	 */
	@Bean
	public ReactiveOAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService() {
		final DefaultReactiveOAuth2UserService delegate = new DefaultReactiveOAuth2UserService();

		return (userRequest) -> delegate.loadUser(userRequest).map((oauth2User) -> {
			Collection<GrantedAuthority> mappedAuthorities = new ArrayList<>(oauth2User.getAuthorities());

			boolean mapped = extractKeycloakRoles(oauth2User.getAttributes(), mappedAuthorities);
			Map<String, Object> accessTokenAttrs = null;
			if (!mapped) {
				accessTokenAttrs = extractRolesFromAccessToken(userRequest.getAccessToken().getTokenValue(),
						mappedAuthorities);
			}

			String userNameAttributeName = userRequest.getClientRegistration()
				.getProviderDetails()
				.getUserInfoEndpoint()
				.getUserNameAttributeName();
			if (userNameAttributeName == null || userNameAttributeName.isEmpty()) {
				userNameAttributeName = "preferred_username";
			}
			if (!oauth2User.getAttributes().containsKey(userNameAttributeName)) {
				userNameAttributeName = "sub";
			}

			final Map<String, Object> finalAccessTokenAttrs = accessTokenAttrs;
			return new DefaultOAuth2User(mappedAuthorities, oauth2User.getAttributes(), userNameAttributeName) {
				@Override
				public String getName() {
					return displayName(getAttributes(), finalAccessTokenAttrs, super::getName);
				}

				@Override
				public Map<String, Object> getAttributes() {
					return mergeAttributes(super.getAttributes(), finalAccessTokenAttrs);
				}
			};
		});
	}

	/**
	 * Resolves the name shown in the UI. Keycloak puts the human-readable handle in
	 * {@code preferred_username}, which may live on the ID token or only on the access
	 * token; the {@code sub} UUID that Spring falls back to is unusable in a UI.
	 * @param attributes the user's merged attributes
	 * @param accessTokenAttributes claims parsed out of the access token, may be null
	 * @param fallback the framework default, used when no readable name is present
	 * @return the name to display
	 */
	static String displayName(Map<String, Object> attributes, Map<String, Object> accessTokenAttributes,
			Supplier<String> fallback) {
		for (Map<String, Object> source : List.of(attributes,
				(accessTokenAttributes != null) ? accessTokenAttributes : Map.<String, Object>of())) {
			Object preferred = source.get("preferred_username");
			if (preferred != null) {
				return preferred.toString();
			}
		}
		Object name = attributes.get("name");
		return (name != null) ? name.toString() : fallback.get();
	}

	/**
	 * @param base the attributes resolved by Spring Security
	 * @param accessTokenAttributes claims parsed out of the access token, may be null
	 * @return the two sets merged, access-token claims winning
	 */
	static Map<String, Object> mergeAttributes(Map<String, Object> base, Map<String, Object> accessTokenAttributes) {
		Map<String, Object> merged = new HashMap<>(base);
		if (accessTokenAttributes != null) {
			merged.putAll(accessTokenAttributes);
		}
		return merged;
	}

	private Map<String, Object> extractRolesFromAccessToken(String tokenValue,
			Collection<GrantedAuthority> mappedAuthorities) {
		try {
			if (tokenValue != null && tokenValue.contains(".")) {
				String[] parts = tokenValue.split("\\.");
				if (parts.length >= 2) {
					String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
					Map<String, Object> attributes = objectMapper.readValue(payload,
							new TypeReference<Map<String, Object>>() {
							});
					extractKeycloakRoles(attributes, mappedAuthorities);
					return attributes;
				}
			}
		}
		catch (Exception ex) {
			// Ignore parsing errors, it might not be a JWT
		}
		return null;
	}

	private boolean extractKeycloakRoles(Map<String, Object> attributes,
			Collection<GrantedAuthority> mappedAuthorities) {
		if (attributes == null) {
			return false;
		}

		boolean found = false;

		// Check orthrus_roles claim
		Object orthrusRolesObj = attributes.get("orthrus_roles");
		if (orthrusRolesObj instanceof List) {
			List<?> orthrusRoles = (List<?>) orthrusRolesObj;
			for (Object role : orthrusRoles) {
				if (role instanceof String) {
					mappedAuthorities.add(new SimpleGrantedAuthority("ROLE_" + ((String) role).toUpperCase()));
					found = true;
				}
			}
		}

		// Check resource_access.orthrus.roles claim
		Object resourceAccessObj = attributes.get("resource_access");
		if (resourceAccessObj instanceof Map) {
			Map<?, ?> resourceAccess = (Map<?, ?>) resourceAccessObj;
			Object orthrusResource = resourceAccess.get("orthrus");
			if (orthrusResource instanceof Map) {
				Map<?, ?> orthrusMap = (Map<?, ?>) orthrusResource;
				Object rolesObj = orthrusMap.get("roles");
				if (rolesObj instanceof List) {
					List<?> roles = (List<?>) rolesObj;
					for (Object role : roles) {
						if (role instanceof String) {
							mappedAuthorities.add(new SimpleGrantedAuthority("ROLE_" + ((String) role).toUpperCase()));
							found = true;
						}
					}
				}
			}
		}

		return found;
	}

}

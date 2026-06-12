package ch.nexsol.orthrusdast.config;

import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;
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
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import java.util.HashMap;

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

		return userRequest -> delegate.loadUser(userRequest).map(oidcUser -> {
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
					if (getAttributes().containsKey("preferred_username")) {
						return getAttributes().get("preferred_username").toString();
					}
					if (finalAccessTokenAttrs != null && finalAccessTokenAttrs.containsKey("preferred_username")) {
						return finalAccessTokenAttrs.get("preferred_username").toString();
					}
					if (getAttributes().containsKey("name")) {
						return getAttributes().get("name").toString();
					}
					return super.getName();
				}

				@Override
				public Map<String, Object> getAttributes() {
					Map<String, Object> attrs = new HashMap<>(super.getAttributes());
					if (finalAccessTokenAttrs != null) {
						attrs.putAll(finalAccessTokenAttrs);
					}
					return attrs;
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

		return userRequest -> delegate.loadUser(userRequest).map(oauth2User -> {
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
					if (getAttributes().containsKey("preferred_username")) {
						return getAttributes().get("preferred_username").toString();
					}
					if (finalAccessTokenAttrs != null && finalAccessTokenAttrs.containsKey("preferred_username")) {
						return finalAccessTokenAttrs.get("preferred_username").toString();
					}
					if (getAttributes().containsKey("name")) {
						return getAttributes().get("name").toString();
					}
					return super.getName();
				}

				@Override
				public Map<String, Object> getAttributes() {
					Map<String, Object> attrs = new HashMap<>(super.getAttributes());
					if (finalAccessTokenAttrs != null) {
						attrs.putAll(finalAccessTokenAttrs);
					}
					return attrs;
				}
			};
		});
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
		catch (Exception e) {
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

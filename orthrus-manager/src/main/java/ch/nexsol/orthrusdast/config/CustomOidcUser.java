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

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;

public class CustomOidcUser extends DefaultOidcUser {

	private final Map<String, Object> accessTokenAttributes;

	public CustomOidcUser(Collection<? extends GrantedAuthority> authorities, OidcIdToken idToken,
			OidcUserInfo userInfo, Map<String, Object> accessTokenAttributes) {
		super(authorities, idToken, userInfo);
		this.accessTokenAttributes = accessTokenAttributes;
	}

	@Override
	public String getName() {
		// Try preferred_username from standard attributes
		if (getAttributes().containsKey("preferred_username")) {
			return getAttributes().get("preferred_username").toString();
		}
		// Try from access token
		if (accessTokenAttributes != null && accessTokenAttributes.containsKey("preferred_username")) {
			return accessTokenAttributes.get("preferred_username").toString();
		}
		// Fallback to name
		if (getAttributes().containsKey("name")) {
			return getAttributes().get("name").toString();
		}
		// Fallback to super (which is sub)
		return super.getName();
	}

	@Override
	public Map<String, Object> getAttributes() {
		Map<String, Object> attrs = new HashMap<>(super.getAttributes());
		if (accessTokenAttributes != null) {
			attrs.putAll(accessTokenAttributes);
		}
		return attrs;
	}

}

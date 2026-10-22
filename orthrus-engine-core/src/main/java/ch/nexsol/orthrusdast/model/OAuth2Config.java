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

/**
 * Configuration for OAuth2 token fetching.
 *
 * @param tokenUrl the token endpoint
 * @param clientId the client id
 * @param clientSecret the client secret
 * @param grantType {@code client_credentials} or {@code password}
 * @param credentials the {@code user:pass} pairs of the password grant
 * @param scope the space-separated scopes to request, or null to request none and let the
 * identity provider apply the client's defaults
 */
public record OAuth2Config(String tokenUrl, String clientId, String clientSecret, String grantType,
		List<String> credentials, String scope) {

	public OAuth2Config {
		scope = (scope != null && !scope.isBlank()) ? scope.strip() : null;
	}

}

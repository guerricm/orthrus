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

package ch.nexsol.orthrusdast.client;

import java.util.List;

import org.junit.jupiter.api.Test;

import ch.nexsol.orthrus.protocol.ai.Credential;
import ch.nexsol.orthrusdast.model.SecurityScheme;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The manager hands credentials back as plain tuples; the worker turns them into the auth
 * schemes its scanners apply, the exact inverse of how the manager resolved them.
 */
class MasterApiClientSchemesTest {

	@Test
	void anAuthorizationHeaderComesBackAsABearerSchemeWithoutItsPrefix() {
		List<SecurityScheme> schemes = MasterApiClient
			.toSchemes(List.of(new Credential("HEADER", "Authorization", "Bearer fresh-token")));

		assertThat(schemes).singleElement().satisfies((scheme) -> {
			assertThat(scheme.type()).isEqualTo(SecurityScheme.AuthType.BEARER);
			assertThat(scheme.value()).isEqualTo("fresh-token");
			assertThat(scheme.toAuthorizationHeaderValue()).isEqualTo("Bearer fresh-token");
		});
	}

	@Test
	void primaryAndSecondaryKeepTheirOrder() {
		List<SecurityScheme> schemes = MasterApiClient
			.toSchemes(List.of(new Credential("HEADER", "Authorization", "Bearer user-a"),
					new Credential("HEADER", "Authorization", "Bearer user-b")));

		assertThat(schemes).extracting(SecurityScheme::value).containsExactly("user-a", "user-b");
	}

	@Test
	void otherLocationsComeBackAsApiKeys() {
		List<SecurityScheme> schemes = MasterApiClient.toSchemes(List.of(new Credential("HEADER", "X-Api-Key", "k1"),
				new Credential("QUERY", "api_key", "k2"), new Credential("COOKIE", "session", "k3")));

		assertThat(schemes).extracting(SecurityScheme::paramLocation)
			.containsExactly(SecurityScheme.ParamLocation.HEADER, SecurityScheme.ParamLocation.QUERY,
					SecurityScheme.ParamLocation.COOKIE);
		assertThat(schemes).extracting(SecurityScheme::value).containsExactly("k1", "k2", "k3");
	}

	@Test
	void anIncompleteCredentialIsDropped() {
		assertThat(MasterApiClient
			.toSchemes(List.of(new Credential("HEADER", "Authorization", null), new Credential("HEADER", null, "v"))))
			.isEmpty();
		assertThat(MasterApiClient.toSchemes(List.of())).isEmpty();
	}

}

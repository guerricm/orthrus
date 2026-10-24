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

package ch.nexsol.orthrus.protocol.node;

import java.util.List;

import ch.nexsol.orthrus.protocol.ai.Credential;

/**
 * Credentials the manager issues for a running job, on demand. A node asks for them when
 * the ones it was dispatched with stop being accepted: OAuth2 tokens are short-lived and
 * a long task can outlive the token it started with. The manager holds the OAuth2
 * settings, so it is the only side that can mint a new token.
 *
 * @param credentials the credentials to attach to every request, possibly empty when the
 * job has no authentication configured
 */
public record JobCredentials(List<Credential> credentials) {

	public JobCredentials {
		credentials = (credentials != null) ? List.copyOf(credentials) : List.of();
	}

}

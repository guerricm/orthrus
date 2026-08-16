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

package ch.nexsol.orthrusai.scanner.wire;

import java.util.List;

/**
 * The orchestrator's shared recon as this node receives it on a scan task. Local copy of
 * the manager's payload so the module stays independent of the other orthrus modules.
 * When present, the node uses these endpoints and context instead of running its own
 * recon.
 *
 * @param baseUrl the base URL the endpoints resolve against
 * @param endpoints the endpoints to scan
 * @param context a short natural-language fingerprint of the target
 * @param credentials credentials to attach to every probe (already resolved by the
 * manager)
 * @param ignoreSslErrors whether the node may trust untrusted certificates
 * @param connectTimeoutMs the connect timeout for probes
 * @param readTimeoutMs the read timeout for probes
 */
public record AiRecon(String baseUrl, List<Endpoint> endpoints, String context, List<Credential> credentials,
		boolean ignoreSslErrors, int connectTimeoutMs, int readTimeoutMs) {

	/**
	 * One endpoint from the shared recon.
	 *
	 * @param method the HTTP method
	 * @param url the absolute URL
	 */
	public record Endpoint(String method, String url) {
	}

	/**
	 * A credential to attach to every request.
	 *
	 * @param location where to place it: HEADER, QUERY or COOKIE
	 * @param name the header/parameter/cookie name
	 * @param value the value to send
	 */
	public record Credential(String location, String name, String value) {
	}

}

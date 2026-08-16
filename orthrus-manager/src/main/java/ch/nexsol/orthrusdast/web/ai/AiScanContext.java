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

package ch.nexsol.orthrusdast.web.ai;

import java.util.List;

/**
 * The resolved picture the manager hands an AI scanner node for a job: the endpoints and
 * fingerprint from the orchestrator's recon, plus the parts of the Test Plan's
 * {@code ScanConfiguration} the node must honour — the credentials to send on every
 * probe, TLS leniency and timeouts. The manager resolves the auth schemes to plain
 * location/name/value tuples so the autonomous node applies them without re-implementing
 * the auth types.
 *
 * @param baseUrl the base URL endpoints resolve against
 * @param endpoints the endpoints to scan
 * @param context a natural-language fingerprint and the operator's scanner selection
 * @param credentials the credentials to attach to every request
 * @param ignoreSslErrors whether the node may trust untrusted certificates
 * @param connectTimeoutMs the connect timeout for probes
 * @param readTimeoutMs the read timeout for probes
 */
public record AiScanContext(String baseUrl, List<Endpoint> endpoints, String context, List<Credential> credentials,
		boolean ignoreSslErrors, int connectTimeoutMs, int readTimeoutMs) {

	/**
	 * One endpoint to scan.
	 *
	 * @param method the HTTP method
	 * @param url the absolute URL
	 */
	public record Endpoint(String method, String url) {
	}

	/**
	 * A credential to attach to every request, already resolved from an auth scheme.
	 *
	 * @param location where to place it: HEADER, QUERY or COOKIE
	 * @param name the header/parameter/cookie name
	 * @param value the value to send
	 */
	public record Credential(String location, String name, String value) {
	}

}

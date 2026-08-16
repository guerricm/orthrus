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

package ch.nexsol.orthrusai.scanner.ai;

import java.util.List;

import ch.nexsol.orthrusai.scanner.wire.AiRecon;

/**
 * The parts of the operator's scan configuration a family agent must honour when it
 * probes: the credentials to send, whether to trust untrusted certificates, and the read
 * timeout. Resolved by the manager and carried on the task; defaults keep the node
 * working standalone.
 *
 * @param credentials credentials to attach to every request
 * @param ignoreSslErrors whether to trust untrusted certificates
 * @param readTimeoutMs the read timeout for probes
 */
public record ProbeConfig(List<AiRecon.Credential> credentials, boolean ignoreSslErrors, int readTimeoutMs) {

	public static ProbeConfig defaults() {
		return new ProbeConfig(List.of(), false, 10000);
	}
}

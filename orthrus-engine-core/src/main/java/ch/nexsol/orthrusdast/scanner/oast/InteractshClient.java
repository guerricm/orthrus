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

package ch.nexsol.orthrusdast.scanner.oast;

import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import ch.nexsol.orthrusdast.config.OrthrusProperties;

/**
 * Out-of-band interaction service backed by an Interactsh-compatible collector.
 *
 * <p>
 * Out-of-band detection is <strong>opt-in</strong> via {@code orthrus.oast.enabled}. When
 * disabled (the default) {@link #isEnabled()} returns false so scanners skip OOB-only
 * probes instead of firing payloads that call back to a collector nobody is listening on.
 * The session domain then points at {@code .oast.invalid}, which is guaranteed not to
 * resolve, making an accidental callback impossible.
 *
 * <p>
 * The full Interactsh wire protocol (RSA session registration and AES-GCM decryption of
 * polled interactions) is intentionally not implemented here: it requires a live
 * collector to validate against. {@link #pollInteractions} therefore returns no
 * interactions even when enabled, and logs once so the gap is visible rather than silent.
 */
@Service
public class InteractshClient implements OastService {

	private static final Logger log = LoggerFactory.getLogger(InteractshClient.class);

	private final boolean enabled;

	private final String serverHost;

	private boolean pollWarningEmitted;

	@Autowired
	public InteractshClient(OrthrusProperties properties) {
		OrthrusProperties.Oast oast = properties.getOast();
		this.enabled = oast.isEnabled() && oast.getServerHost() != null && !oast.getServerHost().isBlank();
		this.serverHost = oast.getServerHost();
		if (oast.isEnabled() && !this.enabled) {
			log.warn("OAST is enabled but no orthrus.oast.server-host is configured; out-of-band checks are disabled.");
		}
	}

	private InteractshClient(boolean enabled, String serverHost) {
		this.enabled = enabled;
		this.serverHost = serverHost;
	}

	/**
	 * A disabled instance for tests and contexts without configuration. Kept private as a
	 * factory (rather than a second public constructor) so Spring has a single,
	 * unambiguous injectable constructor.
	 * @return a disabled OAST client
	 */
	public static InteractshClient disabled() {
		return new InteractshClient(false, null);
	}

	@Override
	public boolean isEnabled() {
		return enabled;
	}

	@Override
	public Mono<OastSession> createSession() {
		String correlationId = UUID.randomUUID().toString().substring(0, 10).replace("-", "");
		// When disabled, use the reserved .invalid TLD so any accidental callback cannot
		// leave the host running the scan.
		String domain = enabled ? correlationId + "." + serverHost : correlationId + ".oast.invalid";
		log.debug("Created OAST session: {} (enabled={})", domain, enabled);
		return Mono.just(new OastSession(correlationId, domain, "orthrus-" + correlationId));
	}

	@Override
	public Flux<OastInteraction> pollInteractions(OastSession session) {
		if (!enabled) {
			return Flux.empty();
		}
		if (!pollWarningEmitted) {
			pollWarningEmitted = true;
			log.warn("OAST polling against '{}' is not yet implemented; blind/out-of-band findings will be missed.",
					serverHost);
		}
		return Flux.empty();
	}

}

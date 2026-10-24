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

package ch.nexsol.orthrusdast.auth;

import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import tools.jackson.databind.ObjectMapper;

import ch.nexsol.orthrus.protocol.ai.Credential;
import ch.nexsol.orthrusdast.model.ScanConfiguration;
import ch.nexsol.orthrusdast.model.SecurityScheme;
import ch.nexsol.orthrusdast.repository.ScanJobRepository;

/**
 * Issues the credentials a node must attach to its probes for a given job.
 *
 * <p>
 * OAuth2 tokens are short-lived and are never stored, so they are minted here from the
 * job's settings: once when a task is dispatched, and again whenever a node asks because
 * the token it was given stopped being accepted. Keeping this on the manager is what lets
 * the OAuth2 client secret stay out of the nodes.
 */
@Service
public class JobCredentialsService {

	private static final Logger log = LoggerFactory.getLogger(JobCredentialsService.class);

	private final ScanJobRepository scanJobRepository;

	private final OAuth2TokenFetcher tokenFetcher;

	private final ObjectMapper objectMapper;

	public JobCredentialsService(ScanJobRepository scanJobRepository, OAuth2TokenFetcher tokenFetcher,
			ObjectMapper objectMapper) {
		this.scanJobRepository = scanJobRepository;
		this.tokenFetcher = tokenFetcher;
		this.objectMapper = objectMapper;
	}

	/**
	 * Issues freshly minted credentials for a job: its OAuth2 tokens are requested again,
	 * and the resulting auth schemes are resolved to plain tuples.
	 * @param jobId the job a node is running a task for
	 * @return the credentials, empty when the job is unknown, unreadable or carries none
	 */
	public Mono<List<Credential>> issueFor(Long jobId) {
		return this.scanJobRepository.findById(jobId)
			.flatMap((job) -> Mono.justOrEmpty(parseConfig(job.getScanConfigurationJson())))
			.flatMap(this::issueFor)
			.defaultIfEmpty(List.of());
	}

	/**
	 * Issues freshly minted credentials for a configuration. A configuration without
	 * OAuth2 settings is resolved as is, so static bearer tokens still come through.
	 * @param config the job's scan configuration
	 * @return the credentials (possibly empty)
	 */
	public Mono<List<Credential>> issueFor(ScanConfiguration config) {
		if (config == null) {
			return Mono.just(List.of());
		}
		if (config.oauth2Config() == null) {
			return Mono.just(resolve(config));
		}
		return this.tokenFetcher.refreshAuth(config).map(JobCredentialsService::resolve).onErrorResume((e) -> {
			log.warn("Could not issue OAuth2 tokens; falling back to the stored credentials: {}", e.getMessage());
			return Mono.just(resolve(config));
		});
	}

	/**
	 * Turns the primary and secondary auth schemes of a configuration into plain
	 * credentials a node attaches to every request.
	 * @param config the configuration, may be null
	 * @return the resolved credentials (possibly empty)
	 */
	public static List<Credential> resolve(ScanConfiguration config) {
		List<Credential> credentials = new ArrayList<>();
		if (config == null) {
			return credentials;
		}
		addCredential(credentials, config.authScheme());
		addCredential(credentials, config.secondaryAuthScheme());
		return credentials;
	}

	private static void addCredential(List<Credential> credentials, SecurityScheme scheme) {
		if (scheme == null || scheme.value() == null || scheme.value().isBlank()) {
			return;
		}
		SecurityScheme.ParamLocation location = (scheme.paramLocation() != null) ? scheme.paramLocation()
				: SecurityScheme.ParamLocation.HEADER;
		switch (location) {
			case QUERY -> {
				if (scheme.paramName() != null) {
					credentials.add(new Credential("QUERY", scheme.paramName(), scheme.value()));
				}
			}
			case COOKIE -> {
				String name = (scheme.paramName() != null) ? scheme.paramName() : scheme.headerName();
				if (name != null) {
					credentials.add(new Credential("COOKIE", name, scheme.value()));
				}
			}
			default -> {
				String name = (scheme.headerName() != null) ? scheme.headerName() : "Authorization";
				credentials.add(new Credential("HEADER", name, scheme.toAuthorizationHeaderValue()));
			}
		}
	}

	private ScanConfiguration parseConfig(String json) {
		if (json == null || json.isBlank()) {
			return null;
		}
		try {
			return this.objectMapper.readValue(json, ScanConfiguration.class);
		}
		catch (RuntimeException ex) {
			log.debug("Could not parse the scan configuration: {}", ex.getMessage());
			return null;
		}
	}

}

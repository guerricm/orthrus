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

import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import tools.jackson.databind.ObjectMapper;

import ch.nexsol.orthrusdast.entity.ScanJobEntity;
import ch.nexsol.orthrusdast.model.ScanConfiguration;
import ch.nexsol.orthrusdast.model.SecurityScheme;

/**
 * Builds the {@link AiScanContext} the manager hands an AI job: it resolves the Test
 * Plan's {@code ScanConfiguration} (auth schemes, TLS leniency, timeouts, scanner
 * selection) and, when the orchestrator is configured, folds in its shared recon
 * (endpoints + fingerprint). The credentials are resolved here so the autonomous node
 * applies them without knowing the auth types. Present even without an orchestrator, so
 * authenticated probing still works.
 */
@Service
public class AiJobReconService {

	private static final Logger log = LoggerFactory.getLogger(AiJobReconService.class);

	private final ObjectProvider<AiOrchestratorClient> orchestratorClient;

	private final ObjectMapper objectMapper;

	public AiJobReconService(ObjectProvider<AiOrchestratorClient> orchestratorClient, ObjectMapper objectMapper) {
		this.orchestratorClient = orchestratorClient;
		this.objectMapper = objectMapper;
	}

	/**
	 * Resolves the job's config and (optionally) the orchestrator recon into the JSON the
	 * dispatcher forwards to the AI node. Empty only when nothing useful could be built.
	 * @param job the AI job being started
	 * @return the serialized {@link AiScanContext}, or empty on failure
	 */
	public Mono<String> contextJsonFor(ScanJobEntity job) {
		ScanConfiguration config = parseConfig(job.getScanConfigurationJson());
		List<AiScanContext.Credential> credentials = resolveCredentials(config);
		String selection = describeSelection(config);
		String host = (config != null) ? config.openapiOverrideHost() : null;

		AiOrchestratorClient client = this.orchestratorClient.getIfAvailable();
		Mono<AiReconResult> recon = (client != null)
				? client.recon(job.getTarget(), host, credentials).onErrorResume((e) -> {
					log.warn("Orchestrator recon of {} failed ({}); node will use local recon", job.getTarget(),
							e.getMessage());
					return Mono.empty();
				}) : Mono.empty();

		return recon.map((result) -> assemble(result, config, credentials, selection))
			.defaultIfEmpty(assemble(null, config, credentials, selection))
			.flatMap((context) -> {
				try {
					return Mono.just(this.objectMapper.writeValueAsString(context));
				}
				catch (RuntimeException ex) {
					log.warn("Could not serialize AI context for job {}: {}", job.getId(), ex.getMessage());
					return Mono.empty();
				}
			});
	}

	private AiScanContext assemble(AiReconResult recon, ScanConfiguration config,
			List<AiScanContext.Credential> credentials, String selection) {
		String baseUrl = (recon != null) ? recon.baseUrl() : null;
		List<AiScanContext.Endpoint> endpoints = new ArrayList<>();
		if (recon != null && recon.endpoints() != null) {
			for (AiReconResult.Endpoint e : recon.endpoints()) {
				endpoints.add(new AiScanContext.Endpoint(e.method(), e.url()));
			}
		}
		String context = joinContext((recon != null) ? recon.context() : null, selection);
		boolean ignoreSsl = config != null && config.ignoreSslErrors();
		int connect = (config != null && config.httpConnectTimeoutMs() > 0) ? config.httpConnectTimeoutMs() : 5000;
		int read = (config != null && config.httpReadTimeoutMs() > 0) ? config.httpReadTimeoutMs() : 10000;
		return new AiScanContext(baseUrl, endpoints, context, credentials, ignoreSsl, connect, read);
	}

	private String joinContext(String reconContext, String selection) {
		StringBuilder sb = new StringBuilder();
		if (reconContext != null && !reconContext.isBlank()) {
			sb.append(reconContext);
		}
		if (selection != null && !selection.isBlank()) {
			if (sb.length() > 0) {
				sb.append(' ');
			}
			sb.append(selection);
		}
		return sb.toString();
	}

	private String describeSelection(ScanConfiguration config) {
		if (config == null) {
			return "";
		}
		List<String> include = config.includeScanners();
		if (include != null && !include.isEmpty()) {
			return "Operator selected these scanners to focus on: " + String.join(", ", include) + ".";
		}
		return "";
	}

	/**
	 * Turns the primary and secondary auth schemes into plain credentials the node
	 * attaches to every request.
	 * @param config the scan configuration, or null
	 * @return the resolved credentials (possibly empty)
	 */
	private List<AiScanContext.Credential> resolveCredentials(ScanConfiguration config) {
		List<AiScanContext.Credential> credentials = new ArrayList<>();
		if (config == null) {
			return credentials;
		}
		addCredential(credentials, config.authScheme());
		addCredential(credentials, config.secondaryAuthScheme());
		return credentials;
	}

	private void addCredential(List<AiScanContext.Credential> credentials, SecurityScheme scheme) {
		if (scheme == null || scheme.value() == null || scheme.value().isBlank()) {
			return;
		}
		SecurityScheme.ParamLocation location = (scheme.paramLocation() != null) ? scheme.paramLocation()
				: SecurityScheme.ParamLocation.HEADER;
		switch (location) {
			case QUERY -> {
				if (scheme.paramName() != null) {
					credentials.add(new AiScanContext.Credential("QUERY", scheme.paramName(), scheme.value()));
				}
			}
			case COOKIE -> {
				String name = (scheme.paramName() != null) ? scheme.paramName() : scheme.headerName();
				if (name != null) {
					credentials.add(new AiScanContext.Credential("COOKIE", name, scheme.value()));
				}
			}
			default -> {
				String name = (scheme.headerName() != null) ? scheme.headerName() : "Authorization";
				credentials.add(new AiScanContext.Credential("HEADER", name, scheme.toAuthorizationHeaderValue()));
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
			log.debug("Could not parse scan configuration for AI context: {}", ex.getMessage());
			return null;
		}
	}

}

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

import ch.nexsol.orthrus.protocol.ai.AiScanContext;
import ch.nexsol.orthrus.protocol.ai.Credential;
import ch.nexsol.orthrus.protocol.ai.Endpoint;
import ch.nexsol.orthrus.protocol.ai.ReconResult;
import ch.nexsol.orthrusdast.entity.ScanJobEntity;
import ch.nexsol.orthrusdast.model.ScanConfiguration;
import ch.nexsol.orthrusdast.model.SecurityScheme;

/**
 * The two halves of what an AI job needs before its tasks can run on a node.
 * <p>
 * {@link #reconJsonFor} asks the orchestrator to fingerprint the target once; the result
 * is persisted on the job and is the only thing stored, so no credential is written to
 * the database twice. {@link #contextJsonFor} then assembles, at dispatch time and in
 * memory, the {@link AiScanContext} a node receives: that stored recon plus the parts of
 * the Test Plan's {@code ScanConfiguration} the node must honour (credentials resolved to
 * plain tuples, TLS leniency, timeouts). Both work without an orchestrator, so
 * authenticated probing still works standalone.
 */
@Service
public class AiJobReconService {

	private static final Logger log = LoggerFactory.getLogger(AiJobReconService.class);

	/**
	 * What the manager stores when no orchestrator recon is available: a settled result
	 * with no endpoints, so the dispatcher releases the job's tasks and each node falls
	 * back to its own local recon.
	 */
	static final ReconResult NO_RECON = new ReconResult(null, List.of(), "");

	private final ObjectProvider<AiOrchestratorClient> orchestratorClient;

	private final ObjectMapper objectMapper;

	public AiJobReconService(ObjectProvider<AiOrchestratorClient> orchestratorClient, ObjectMapper objectMapper) {
		this.orchestratorClient = orchestratorClient;
		this.objectMapper = objectMapper;
	}

	/**
	 * Recons the job's target through the orchestrator, sending the Test Plan's
	 * credentials so a protected OpenAPI document can be read. Never empty and never
	 * fails: without an orchestrator, or when it cannot be reached, the result is
	 * {@link #NO_RECON}, so the job is marked as reconned either way and its tasks are
	 * released.
	 * @param job the running AI job
	 * @return the serialized {@link ReconResult} to store on the job
	 */
	public Mono<String> reconJsonFor(ScanJobEntity job) {
		AiOrchestratorClient client = this.orchestratorClient.getIfAvailable();
		if (client == null) {
			return serialize(NO_RECON);
		}
		ScanConfiguration config = parseConfig(job.getScanConfigurationJson());
		String host = (config != null) ? config.openapiOverrideHost() : null;
		return client.recon(job.getTarget(), host, resolveCredentials(config)).onErrorResume((e) -> {
			log.warn("Orchestrator recon of {} failed ({}); nodes will use local recon", job.getTarget(),
					e.getMessage());
			return Mono.just(new ReconResult(null, List.of(), "Orchestrator recon unavailable: " + e.getMessage()));
		}).flatMap(this::serialize);
	}

	private Mono<String> serialize(ReconResult recon) {
		return Mono.fromCallable(() -> this.objectMapper.writeValueAsString(recon))
			.onErrorResume((e) -> Mono.fromCallable(() -> this.objectMapper.writeValueAsString(NO_RECON)));
	}

	/**
	 * Assembles the context a node receives for one of the job's tasks: the stored recon
	 * plus the credentials, TLS leniency and timeouts resolved from the job's
	 * configuration. Pure and in-memory; called at dispatch, never persisted.
	 * @param job the AI job being dispatched
	 * @return the serialized {@link AiScanContext}, or null when it cannot be built
	 */
	public String contextJsonFor(ScanJobEntity job) {
		ScanConfiguration config = parseConfig(job.getScanConfigurationJson());
		ReconResult recon = parseRecon(job.getAiRecon());
		List<Endpoint> endpoints = (recon.endpoints() != null) ? recon.endpoints() : List.of();
		String context = joinContext(recon.context(), describeSelection(config));
		boolean ignoreSsl = config != null && config.ignoreSslErrors();
		int connect = (config != null && config.httpConnectTimeoutMs() > 0) ? config.httpConnectTimeoutMs() : 5000;
		int read = (config != null && config.httpReadTimeoutMs() > 0) ? config.httpReadTimeoutMs() : 10000;
		AiScanContext scanContext = new AiScanContext(recon.baseUrl(), endpoints, context, resolveCredentials(config),
				ignoreSsl, connect, read);
		try {
			return this.objectMapper.writeValueAsString(scanContext);
		}
		catch (RuntimeException ex) {
			log.warn("Could not serialize AI context for job {}: {}", job.getId(), ex.getMessage());
			return null;
		}
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
	private List<Credential> resolveCredentials(ScanConfiguration config) {
		List<Credential> credentials = new ArrayList<>();
		if (config == null) {
			return credentials;
		}
		addCredential(credentials, config.authScheme());
		addCredential(credentials, config.secondaryAuthScheme());
		return credentials;
	}

	private void addCredential(List<Credential> credentials, SecurityScheme scheme) {
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
			log.debug("Could not parse scan configuration for AI context: {}", ex.getMessage());
			return null;
		}
	}

	private ReconResult parseRecon(String json) {
		if (json == null || json.isBlank()) {
			return NO_RECON;
		}
		try {
			return this.objectMapper.readValue(json, ReconResult.class);
		}
		catch (RuntimeException ex) {
			log.warn("Could not parse the stored recon; nodes will use local recon: {}", ex.getMessage());
			return NO_RECON;
		}
	}

}

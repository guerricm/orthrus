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

package ch.nexsol.orthrusdast.plan;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import tools.jackson.databind.ObjectMapper;

import ch.nexsol.orthrusdast.entity.TestPlanEntity;
import ch.nexsol.orthrusdast.model.OAuth2Config;
import ch.nexsol.orthrusdast.model.ScanConfiguration;
import ch.nexsol.orthrusdast.model.SecurityScheme;
import ch.nexsol.orthrusdast.repository.TestPlanRepository;

/**
 * Moves test plans between Orthrus instances.
 * <p>
 * Exports are meant to be shared or committed, so every secret a plan carries leaves as
 * {@link #MASK}: the OIDC client secret and credentials, the bearer tokens and API keys
 * of the auth schemes, and the Kubernetes token. Import treats that placeholder as an
 * absent value and reports which plans still need their secrets filled in.
 */
@Service
public class TestPlanPortabilityService {

	/**
	 * Stands in for any secret in an exported plan.
	 */
	public static final String MASK = "****";

	private static final String IMPORT_SUFFIX = " (imported";

	private static final Logger log = LoggerFactory.getLogger(TestPlanPortabilityService.class);

	private final TestPlanRepository testPlanRepository;

	private final ObjectMapper objectMapper;

	public TestPlanPortabilityService(TestPlanRepository testPlanRepository, ObjectMapper objectMapper) {
		this.testPlanRepository = testPlanRepository;
		this.objectMapper = objectMapper;
	}

	/**
	 * @param plans the plans to export
	 * @return a transfer document carrying no secret
	 */
	public TestPlanExport export(List<TestPlanEntity> plans) {
		List<TestPlanExport.Plan> exported = plans.stream()
			.map((plan) -> new TestPlanExport.Plan(plan.getName(), plan.getDescription(), plan.getDiscovererId(),
					plan.getTarget(), maskSecrets(readConfiguration(plan))))
			.toList();
		return new TestPlanExport(TestPlanExport.CURRENT_VERSION, Instant.now(), exported);
	}

	/**
	 * Creates a plan for each entry in the document. Existing plans are never
	 * overwritten: a name already in use is suffixed instead.
	 * @param export the document to import
	 * @return what was created, and which plans are missing their secrets
	 */
	public Mono<ImportReport> importPlans(TestPlanExport export) {
		if (export == null || export.formatVersion() != TestPlanExport.CURRENT_VERSION) {
			int version = (export != null) ? export.formatVersion() : 0;
			return Mono.error(new IllegalArgumentException("Unsupported test plan export version: " + version
					+ ". This build reads version " + TestPlanExport.CURRENT_VERSION + "."));
		}

		List<TestPlanExport.Plan> plans = (export.plans() != null) ? export.plans() : List.of();

		return this.testPlanRepository.findAll()
			.map(TestPlanEntity::getName)
			.collect(HashSet<String>::new, Set::add)
			.flatMap((takenNames) -> {
				List<String> imported = new ArrayList<>();
				List<String> needingSecrets = new ArrayList<>();

				return Flux.fromIterable(plans).concatMap((plan) -> {
					StrippedConfiguration stripped = stripMaskedSecrets(plan.configuration());
					String name = availableName(plan.name(), takenNames);
					takenNames.add(name);
					imported.add(name);
					if (stripped.hadMaskedSecrets()) {
						needingSecrets.add(name);
					}

					TestPlanEntity entity = new TestPlanEntity(name, plan.description(), plan.discovererId(),
							plan.target(), this.objectMapper.writeValueAsString(stripped.configuration()));
					return this.testPlanRepository.save(entity);
				}).then(Mono.fromSupplier(() -> new ImportReport(List.copyOf(imported), List.copyOf(needingSecrets))));
			});
	}

	private ScanConfiguration readConfiguration(TestPlanEntity plan) {
		try {
			return this.objectMapper.readValue(plan.getScanConfigurationJson(), ScanConfiguration.class);
		}
		catch (RuntimeException ex) {
			log.warn("Plan {} has an unreadable configuration; exporting defaults instead", plan.getId(), ex);
			return ScanConfiguration.defaults();
		}
	}

	private String availableName(String requested, Set<String> taken) {
		String base = (requested != null && !requested.isBlank()) ? requested : "Imported plan";
		if (!taken.contains(base)) {
			return base;
		}
		String candidate = base + IMPORT_SUFFIX + ")";
		int attempt = 2;
		while (taken.contains(candidate)) {
			candidate = base + IMPORT_SUFFIX + " " + attempt + ")";
			attempt++;
		}
		return candidate;
	}

	private ScanConfiguration maskSecrets(ScanConfiguration config) {
		if (config == null) {
			return null;
		}
		return new ScanConfiguration(config.includeScanners(), config.excludeScanners(), config.concurrency(),
				config.httpConnectTimeoutMs(), config.httpReadTimeoutMs(), config.ignoreSslErrors(),
				config.reportFormat(), maskScheme(config.authScheme()), maskScheme(config.secondaryAuthScheme()),
				config.language(), config.includePassed(), config.gatewayType(), config.appUrl(),
				maskSecret(config.k8sToken()), maskOauth(config.oauth2Config()), config.openapiOverrideHost());
	}

	private String maskSecret(String secret) {
		return (secret == null || secret.isBlank()) ? secret : MASK;
	}

	private SecurityScheme maskScheme(SecurityScheme scheme) {
		if (scheme == null) {
			return null;
		}
		return new SecurityScheme(scheme.type(), maskSecret(scheme.value()), scheme.headerName(), scheme.paramName(),
				scheme.paramLocation());
	}

	private OAuth2Config maskOauth(OAuth2Config oauth) {
		if (oauth == null) {
			return null;
		}
		List<String> credentials = (oauth.credentials() != null)
				? oauth.credentials().stream().map(TestPlanPortabilityService::maskCredential).toList() : null;
		return new OAuth2Config(oauth.tokenUrl(), oauth.clientId(), maskSecret(oauth.clientSecret()), oauth.grantType(),
				credentials);
	}

	/**
	 * Keeps the user of a {@code user:password} pair, which is context rather than
	 * secret, and masks the password.
	 * @param credential the credential as stored
	 * @return the credential with its secret removed
	 */
	private static String maskCredential(String credential) {
		if (credential == null || credential.isBlank()) {
			return credential;
		}
		int separator = credential.indexOf(':');
		return (separator >= 0) ? credential.substring(0, separator + 1) + MASK : MASK;
	}

	/**
	 * Removes the placeholders an export left behind, so a masked value is never stored
	 * as if it were the real secret.
	 * @param config the imported configuration
	 * @return the configuration without placeholders, and whether any were found
	 */
	private StrippedConfiguration stripMaskedSecrets(ScanConfiguration config) {
		if (config == null) {
			return new StrippedConfiguration(ScanConfiguration.defaults(), false);
		}

		boolean masked = isMasked(config.k8sToken()) || isMasked(schemeValue(config.authScheme()))
				|| isMasked(schemeValue(config.secondaryAuthScheme()));

		OAuth2Config oauth = config.oauth2Config();
		OAuth2Config strippedOauth = oauth;
		if (oauth != null) {
			List<String> credentials = (oauth.credentials() != null)
					? oauth.credentials().stream().filter((c) -> !hasMaskedPassword(c)).toList() : null;
			boolean droppedCredentials = oauth.credentials() != null
					&& credentials.size() != oauth.credentials().size();
			masked = masked || isMasked(oauth.clientSecret()) || droppedCredentials;
			strippedOauth = new OAuth2Config(oauth.tokenUrl(), oauth.clientId(), stripMask(oauth.clientSecret()),
					oauth.grantType(), credentials);
		}

		ScanConfiguration stripped = new ScanConfiguration(config.includeScanners(), config.excludeScanners(),
				config.concurrency(), config.httpConnectTimeoutMs(), config.httpReadTimeoutMs(),
				config.ignoreSslErrors(), config.reportFormat(), stripScheme(config.authScheme()),
				stripScheme(config.secondaryAuthScheme()), config.language(), config.includePassed(),
				config.gatewayType(), config.appUrl(), stripMask(config.k8sToken()), strippedOauth,
				config.openapiOverrideHost());

		return new StrippedConfiguration(stripped, masked);
	}

	private static String schemeValue(SecurityScheme scheme) {
		return (scheme != null) ? scheme.value() : null;
	}

	private static SecurityScheme stripScheme(SecurityScheme scheme) {
		if (scheme == null) {
			return null;
		}
		return new SecurityScheme(scheme.type(), stripMask(scheme.value()), scheme.headerName(), scheme.paramName(),
				scheme.paramLocation());
	}

	private static boolean isMasked(String value) {
		return MASK.equals(value);
	}

	private static String stripMask(String value) {
		return isMasked(value) ? null : value;
	}

	private static boolean hasMaskedPassword(String credential) {
		return credential != null && (isMasked(credential) || credential.endsWith(":" + MASK));
	}

	private record StrippedConfiguration(ScanConfiguration configuration, boolean hadMaskedSecrets) {
	}

	/**
	 * @param imported the names the plans were created under
	 * @param plansNeedingSecrets plans whose secrets were masked and must be filled in
	 */
	public record ImportReport(List<String> imported, List<String> plansNeedingSecrets) {
	}

}

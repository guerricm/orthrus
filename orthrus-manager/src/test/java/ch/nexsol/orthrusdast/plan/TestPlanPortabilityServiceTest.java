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

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import tools.jackson.databind.ObjectMapper;

import ch.nexsol.orthrusdast.entity.TestPlanEntity;
import ch.nexsol.orthrusdast.model.GatewayType;
import ch.nexsol.orthrusdast.model.OAuth2Config;
import ch.nexsol.orthrusdast.model.ScanConfiguration;
import ch.nexsol.orthrusdast.model.SecurityScheme;
import ch.nexsol.orthrusdast.repository.TestPlanRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * An export is meant to be shared or committed, so the central concern here is that no
 * secret survives the round trip and that a masked value is never imported back as if it
 * were real.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class TestPlanPortabilityServiceTest {

	private static final String SECRET = "sup3r-s3cret";

	@Mock
	private TestPlanRepository testPlanRepository;

	private final ObjectMapper objectMapper = new ObjectMapper();

	private final List<TestPlanEntity> saved = new ArrayList<>();

	private TestPlanPortabilityService service;

	@BeforeEach
	void setUp() {
		this.service = new TestPlanPortabilityService(this.testPlanRepository, this.objectMapper);
		when(this.testPlanRepository.save(any(TestPlanEntity.class))).thenAnswer((invocation) -> {
			TestPlanEntity plan = invocation.getArgument(0);
			this.saved.add(plan);
			return Mono.just(plan);
		});
		when(this.testPlanRepository.findAll()).thenReturn(Flux.empty());
	}

	@Test
	void theOidcClientSecretIsMasked() {
		TestPlanExport export = this.service.export(List.of(planWith(configWithSecrets())));

		OAuth2Config exported = export.plans().get(0).configuration().oauth2Config();
		assertThat(exported.clientSecret()).isEqualTo(TestPlanPortabilityService.MASK);
		assertThat(exported.clientId()).isEqualTo("orthrus-client");
		assertThat(exported.tokenUrl()).isEqualTo("https://idp.example/token");
	}

	@Test
	void oidcCredentialsKeepTheirUserButLoseTheirPassword() {
		TestPlanExport export = this.service.export(List.of(planWith(configWithSecrets())));

		assertThat(export.plans().get(0).configuration().oauth2Config().credentials())
			.containsExactly("alice:" + TestPlanPortabilityService.MASK, "bob:" + TestPlanPortabilityService.MASK);
	}

	@Test
	void authTokensAndTheKubernetesTokenAreMaskedToo() {
		TestPlanExport export = this.service.export(List.of(planWith(configWithSecrets())));
		ScanConfiguration exported = export.plans().get(0).configuration();

		assertThat(exported.authScheme().value()).isEqualTo(TestPlanPortabilityService.MASK);
		assertThat(exported.secondaryAuthScheme().value()).isEqualTo(TestPlanPortabilityService.MASK);
		assertThat(exported.k8sToken()).isEqualTo(TestPlanPortabilityService.MASK);
		// The non-secret shape of the scheme is worth keeping.
		assertThat(exported.authScheme().headerName()).isEqualTo("Authorization");
		assertThat(exported.authScheme().type()).isEqualTo(SecurityScheme.AuthType.BEARER);
	}

	@Test
	void noSecretAppearsAnywhereInTheSerialisedDocument() {
		TestPlanExport export = this.service.export(List.of(planWith(configWithSecrets())));

		assertThat(this.objectMapper.writeValueAsString(export)).doesNotContain(SECRET)
			.doesNotContain("alice-pw")
			.doesNotContain("k8s-token");
	}

	@Test
	void everythingThatIsNotSecretSurvivesTheExport() {
		TestPlanExport export = this.service.export(List.of(planWith(configWithSecrets())));
		TestPlanExport.Plan plan = export.plans().get(0);

		assertThat(plan.name()).isEqualTo("Nightly");
		assertThat(plan.target()).isEqualTo("https://api.example");
		assertThat(plan.discovererId()).isEqualTo("openapi");
		assertThat(plan.configuration().concurrency()).isEqualTo(4);
		assertThat(plan.configuration().excludeScanners()).containsExactly("ssti");
		assertThat(export.formatVersion()).isEqualTo(TestPlanExport.CURRENT_VERSION);
	}

	@Test
	void aMaskedSecretIsNeverImportedAsARealOne() {
		TestPlanExport export = this.service.export(List.of(planWith(configWithSecrets())));

		TestPlanPortabilityService.ImportReport report = this.service.importPlans(export).block();

		ScanConfiguration imported = this.objectMapper.readValue(this.saved.get(0).getScanConfigurationJson(),
				ScanConfiguration.class);
		assertThat(imported.oauth2Config().clientSecret()).isNull();
		assertThat(imported.oauth2Config().credentials()).isEmpty();
		assertThat(imported.authScheme().value()).isNull();
		assertThat(imported.k8sToken()).isNull();
		assertThat(report.plansNeedingSecrets()).containsExactly("Nightly");
	}

	@Test
	void importKeepsTheConfigurationThatCarriesNoSecret() {
		TestPlanExport export = this.service.export(List.of(planWith(configWithSecrets())));

		this.service.importPlans(export).block();

		ScanConfiguration imported = this.objectMapper.readValue(this.saved.get(0).getScanConfigurationJson(),
				ScanConfiguration.class);
		assertThat(imported.concurrency()).isEqualTo(4);
		assertThat(imported.excludeScanners()).containsExactly("ssti");
		assertThat(imported.oauth2Config().tokenUrl()).isEqualTo("https://idp.example/token");
		assertThat(imported.oauth2Config().clientId()).isEqualTo("orthrus-client");
		assertThat(this.saved.get(0).getTarget()).isEqualTo("https://api.example");
	}

	@Test
	void aPlanCarryingNoSecretIsNotFlagged() {
		ScanConfiguration plain = ScanConfiguration.defaults();
		TestPlanExport export = this.service.export(List.of(planWith(plain)));

		TestPlanPortabilityService.ImportReport report = this.service.importPlans(export).block();

		assertThat(report.plansNeedingSecrets()).isEmpty();
		assertThat(report.imported()).containsExactly("Nightly");
	}

	@Test
	void importingOntoAnExistingNameCreatesACopyRatherThanOverwriting() {
		when(this.testPlanRepository.findAll())
			.thenReturn(Flux.just(planWith(ScanConfiguration.defaults()), renamed("Nightly (imported)")));
		TestPlanExport export = this.service.export(List.of(planWith(ScanConfiguration.defaults())));

		TestPlanPortabilityService.ImportReport report = this.service.importPlans(export).block();

		assertThat(this.saved.get(0).getName()).isEqualTo("Nightly (imported 2)");
		assertThat(report.imported()).containsExactly("Nightly (imported 2)");
	}

	@Test
	void aDocumentFromAnUnknownFormatVersionIsRejected() {
		TestPlanExport future = new TestPlanExport(TestPlanExport.CURRENT_VERSION + 1, null, List.of());

		assertThat(this.service.importPlans(future).map((r) -> "ok").onErrorReturn("rejected").block())
			.isEqualTo("rejected");
	}

	private TestPlanEntity planWith(ScanConfiguration config) {
		TestPlanEntity plan = new TestPlanEntity("Nightly", "Nightly regression", "openapi", "https://api.example",
				this.objectMapper.writeValueAsString(config));
		plan.setId(1L);
		return plan;
	}

	private TestPlanEntity renamed(String name) {
		TestPlanEntity plan = planWith(ScanConfiguration.defaults());
		plan.setName(name);
		return plan;
	}

	private ScanConfiguration configWithSecrets() {
		return new ScanConfiguration(List.of(), List.of("ssti"), 4, 5000, 10000, false, "json",
				SecurityScheme.bearer(SECRET),
				new SecurityScheme(SecurityScheme.AuthType.API_KEY, SECRET, "X-Api-Key", null,
						SecurityScheme.ParamLocation.HEADER),
				"en", false, GatewayType.AUTO, "https://app.example", "k8s-token",
				new OAuth2Config("https://idp.example/token", "orthrus-client", SECRET, "password",
						List.of("alice:alice-pw", "bob:bob-pw")),
				null);
	}

}

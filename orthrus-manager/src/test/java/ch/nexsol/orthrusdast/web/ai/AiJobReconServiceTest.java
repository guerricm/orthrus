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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import tools.jackson.databind.ObjectMapper;

import ch.nexsol.orthrus.protocol.ai.AiScanContext;
import ch.nexsol.orthrus.protocol.ai.Credential;
import ch.nexsol.orthrus.protocol.ai.Endpoint;
import ch.nexsol.orthrus.protocol.ai.ReconResult;
import ch.nexsol.orthrusdast.entity.ScanJobEntity;
import ch.nexsol.orthrusdast.model.JobStatus;
import ch.nexsol.orthrusdast.model.ScanConfiguration;
import ch.nexsol.orthrusdast.model.SecurityScheme;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The stored recon never carries credentials; the context handed to a node does, resolved
 * from the Test Plan at dispatch time. Both halves work with or without an orchestrator.
 */
@ExtendWith(MockitoExtension.class)
class AiJobReconServiceTest {

	@Mock
	private ObjectProvider<AiOrchestratorClient> orchestratorClient;

	@Mock
	private AiOrchestratorClient client;

	private final ObjectMapper objectMapper = new ObjectMapper();

	private AiJobReconService service;

	@BeforeEach
	void setUp() {
		this.service = new AiJobReconService(this.orchestratorClient, this.objectMapper);
	}

	@Test
	void resolvesBearerAuthIntoAHeaderCredentialAtDispatch() {
		ScanJobEntity job = job(
				ScanConfiguration.defaults().withAuthSchemes(SecurityScheme.bearer("secret-token"), null));

		AiScanContext context = this.objectMapper.readValue(this.service.contextJsonFor(job), AiScanContext.class);

		assertThat(context.credentials()).hasSize(1);
		Credential credential = context.credentials().get(0);
		assertThat(credential.location()).isEqualTo("HEADER");
		assertThat(credential.name()).isEqualTo("Authorization");
		assertThat(credential.value()).isEqualTo("Bearer secret-token");
		// No stored recon, so no endpoints; the node falls back to its own recon.
		assertThat(context.endpoints()).isEmpty();
	}

	@Test
	void foldsTheStoredReconIntoTheContext() {
		ScanJobEntity job = job(ScanConfiguration.defaults());
		job.setAiRecon(this.objectMapper.writeValueAsString(new ReconResult("http://app.test/api",
				List.of(new Endpoint("GET", "http://app.test/api/users")), "Server=nginx")));

		AiScanContext context = this.objectMapper.readValue(this.service.contextJsonFor(job), AiScanContext.class);

		assertThat(context.baseUrl()).isEqualTo("http://app.test/api");
		assertThat(context.endpoints()).containsExactly(new Endpoint("GET", "http://app.test/api/users"));
		assertThat(context.context()).isEqualTo("Server=nginx");
	}

	@Test
	void withoutAnOrchestratorTheReconSettlesToAnEmptyResult() {
		when(this.orchestratorClient.getIfAvailable()).thenReturn(null);

		StepVerifier.create(this.service.reconJsonFor(job(ScanConfiguration.defaults())))
			.assertNext(
					(json) -> assertThat(this.objectMapper.readValue(json, ReconResult.class).endpoints()).isEmpty())
			.verifyComplete();
	}

	@Test
	void theOrchestratorReconIsSentTheCredentialsButOnlyTheReconIsStored() {
		when(this.orchestratorClient.getIfAvailable()).thenReturn(this.client);
		ReconResult recon = new ReconResult("http://app.test", List.of(new Endpoint("GET", "http://app.test/x")),
				"ctx");
		when(this.client.recon(eq("https://api.test"), any(), anyList())).thenReturn(Mono.just(recon));
		ScanJobEntity job = job(
				ScanConfiguration.defaults().withAuthSchemes(SecurityScheme.bearer("secret-token"), null));

		StepVerifier.create(this.service.reconJsonFor(job)).assertNext((json) -> {
			assertThat(json).doesNotContain("secret-token");
			assertThat(this.objectMapper.readValue(json, ReconResult.class)).isEqualTo(recon);
		}).verifyComplete();

		verify(this.client).recon(eq("https://api.test"), any(),
				eq(List.of(new Credential("HEADER", "Authorization", "Bearer secret-token"))));
	}

	@Test
	void anUnreachableOrchestratorStillSettlesTheReconSoTasksAreReleased() {
		when(this.orchestratorClient.getIfAvailable()).thenReturn(this.client);
		when(this.client.recon(any(), any(), anyList())).thenReturn(Mono.error(new IllegalStateException("down")));

		StepVerifier.create(this.service.reconJsonFor(job(ScanConfiguration.defaults()))).assertNext((json) -> {
			ReconResult recon = this.objectMapper.readValue(json, ReconResult.class);
			assertThat(recon.endpoints()).isEmpty();
			assertThat(recon.context()).contains("down");
		}).verifyComplete();
	}

	private ScanJobEntity job(ScanConfiguration config) {
		return new ScanJobEntity("openapi", "https://api.test", this.objectMapper.writeValueAsString(config),
				JobStatus.RUNNING, 1L);
	}

}

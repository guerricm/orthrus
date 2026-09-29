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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import tools.jackson.databind.ObjectMapper;

import ch.nexsol.orthrus.protocol.ai.AiScanContext;
import ch.nexsol.orthrus.protocol.ai.Credential;
import ch.nexsol.orthrusdast.entity.ScanJobEntity;
import ch.nexsol.orthrusdast.model.JobStatus;
import ch.nexsol.orthrusdast.model.ScanConfiguration;
import ch.nexsol.orthrusdast.model.SecurityScheme;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Without an orchestrator the service still resolves the Test Plan's auth into plain
 * credentials the node can apply, so authenticated probing works standalone. The
 * {@link org.springframework.beans.factory.ObjectProvider} yields no client here.
 */
@ExtendWith(MockitoExtension.class)
class AiJobReconServiceTest {

	@Mock
	private org.springframework.beans.factory.ObjectProvider<AiOrchestratorClient> orchestratorClient;

	private final ObjectMapper objectMapper = new ObjectMapper();

	@Test
	void resolvesBearerAuthIntoAHeaderCredentialWithoutAnOrchestrator() {
		AiJobReconService service = new AiJobReconService(this.orchestratorClient, this.objectMapper);
		ScanConfiguration config = ScanConfiguration.defaults()
			.withAuthSchemes(SecurityScheme.bearer("secret-token"), null);
		ScanJobEntity job = new ScanJobEntity("openapi", "https://api.test",
				this.objectMapper.writeValueAsString(config), JobStatus.PENDING, 1L);

		String json = service.contextJsonFor(job).block();

		AiScanContext context = this.objectMapper.readValue(json, AiScanContext.class);
		assertThat(context.credentials()).hasSize(1);
		Credential credential = context.credentials().get(0);
		assertThat(credential.location()).isEqualTo("HEADER");
		assertThat(credential.name()).isEqualTo("Authorization");
		assertThat(credential.value()).isEqualTo("Bearer secret-token");
		// No orchestrator, so no endpoints; the node falls back to its own recon.
		assertThat(context.endpoints()).isEmpty();
	}

}

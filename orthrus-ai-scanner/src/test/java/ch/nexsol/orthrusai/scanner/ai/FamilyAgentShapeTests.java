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

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.web.reactive.function.client.WebClient;
import tools.jackson.databind.ObjectMapper;

import ch.nexsol.orthrus.protocol.ai.Endpoint;
import ch.nexsol.orthrusai.scanner.config.AiScannerProperties;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * The operation shape read from the API spec is put in the prompt, so the agent forges
 * requests from the real parameters and body instead of guessing. An endpoint recon could
 * not read a spec for carries no shape, and the prompt stays as it was.
 */
class FamilyAgentShapeTests {

	private final ChatClient chatClient = mock(ChatClient.class, RETURNS_DEEP_STUBS);

	private final FamilyAgent agent = new FamilyAgent(this.chatClient, WebClient.builder(), new ScopeGuard(),
			new ObjectMapper(), new AiScannerProperties(), new AgentActivity());

	@Test
	void putsParametersAndBodySchemaInThePrompt() {
		Endpoint endpoint = new Endpoint("POST", "http://app.test/api/pet/{id}",
				List.of(new Endpoint.Parameter("id", "path", "integer", true)),
				"Pet { id: integer, name: string (required), status: string }");

		this.agent.scan("INJECTION", endpoint, null, ProbeConfig.defaults());

		assertThat(captureUserPrompt()).contains("Operation shape from the API spec")
			.contains("path parameter id (integer, required)")
			.contains("request body: Pet { id: integer, name: string (required), status: string }");
	}

	@Test
	void saysNothingAboutShapeWhenReconFoundNone() {
		this.agent.scan("INJECTION", new Endpoint("GET", "http://app.test/api/health"), null, ProbeConfig.defaults());

		assertThat(captureUserPrompt()).doesNotContain("Operation shape");
	}

	private String captureUserPrompt() {
		ArgumentCaptor<String> userCaptor = ArgumentCaptor.forClass(String.class);
		verify(this.chatClient.prompt().system(anyString())).user(userCaptor.capture());
		return userCaptor.getValue();
	}

}

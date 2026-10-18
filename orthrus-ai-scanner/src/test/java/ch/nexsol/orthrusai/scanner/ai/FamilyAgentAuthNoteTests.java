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

import ch.nexsol.orthrus.protocol.ai.Credential;
import ch.nexsol.orthrus.protocol.ai.Endpoint;
import ch.nexsol.orthrusai.scanner.config.AiScannerProperties;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Configured credentials are attached to probes silently, so the agent is told their
 * location and name in the prompt. Without that, a JWT or BOLA agent would judge its
 * subject absent on an authenticated endpoint and stop too early. The credential values
 * are never put in the prompt.
 */
class FamilyAgentAuthNoteTests {

	private final ChatClient chatClient = mock(ChatClient.class, RETURNS_DEEP_STUBS);

	private final FamilyAgent agent = new FamilyAgent(this.chatClient, WebClient.builder(), new ScopeGuard(),
			new ObjectMapper(), new AiScannerProperties(), new AgentActivity());

	private final Endpoint endpoint = new Endpoint("GET", "http://app.test/api/pet/{petId}");

	@Test
	void announcesConfiguredCredentialsByLocationAndNameWithoutTheirValues() {
		List<Credential> credentials = List.of(new Credential("HEADER", "Authorization", "Bearer super-secret"),
				new Credential("COOKIE", "session", "s1"));

		this.agent.scan("JWT", this.endpoint, null, new ProbeConfig(credentials, false, 10000));

		String userPrompt = captureUserPrompt();
		assertThat(userPrompt).contains("HEADER Authorization")
			.contains("COOKIE session")
			.contains("Treat the endpoint as authenticated")
			.doesNotContain("super-secret")
			.doesNotContain("s1");
	}

	@Test
	void saysNothingAboutAuthWhenNoCredentialsAreConfigured() {
		this.agent.scan("JWT", this.endpoint, null, ProbeConfig.defaults());

		assertThat(captureUserPrompt()).doesNotContain("Treat the endpoint as authenticated");
	}

	private String captureUserPrompt() {
		ArgumentCaptor<String> userCaptor = ArgumentCaptor.forClass(String.class);
		verify(this.chatClient.prompt().system(anyString())).user(userCaptor.capture());
		return userCaptor.getValue();
	}

}

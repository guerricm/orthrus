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

import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.web.reactive.function.client.WebClient;
import tools.jackson.databind.ObjectMapper;

import ch.nexsol.orthrus.protocol.ai.Endpoint;
import ch.nexsol.orthrusai.scanner.config.AiScannerProperties;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * An agent counts as active for exactly the duration of its LLM loop, whether the loop
 * returns or fails, so the node never reports agents that are gone.
 */
class FamilyAgentActivityTests {

	private final ChatClient chatClient = mock(ChatClient.class, RETURNS_DEEP_STUBS);

	private final AgentActivity activity = new AgentActivity();

	private final FamilyAgent agent = new FamilyAgent(this.chatClient, WebClient.builder(), new ScopeGuard(),
			new ObjectMapper(), new AiScannerProperties(), this.activity);

	private final Endpoint endpoint = new Endpoint("GET", "http://app.test/api/pet/{petId}");

	@Test
	void anAgentCountsWhileItsLoopRunsAndStopsCountingWhenItReturns() {
		AtomicInteger seenDuringLoop = new AtomicInteger(-1);
		when(this.chatClient.prompt().system(anyString()).user(anyString()).tools(any(), any()).call().content())
			.thenAnswer((invocation) -> {
				seenDuringLoop.set(this.activity.active());
				return "done";
			});

		this.agent.scan("INJECTION", this.endpoint, null, ProbeConfig.defaults());

		assertThat(seenDuringLoop).hasValue(1);
		assertThat(this.activity.active()).isZero();
	}

	@Test
	void aFailingAgentStopsCounting() {
		when(this.chatClient.prompt().system(anyString()).user(anyString()).tools(any(), any()).call().content())
			.thenThrow(new IllegalStateException("model 'mistral' not found"));

		this.agent.scan("INJECTION", this.endpoint, null, ProbeConfig.defaults());

		assertThat(this.activity.active()).isZero();
	}

}

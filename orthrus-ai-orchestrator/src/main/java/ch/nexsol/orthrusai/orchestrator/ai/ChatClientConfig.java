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

package ch.nexsol.orthrusai.orchestrator.ai;

import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.prompt.ChatOptions;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import ch.nexsol.orthrusai.orchestrator.config.AiOrchestratorProperties;

/**
 * Builds the orchestrator's {@link ChatClient} from the auto-configured provider. Active
 * only when the LLM planner is enabled, so the module still boots without model
 * credentials.
 */
@Configuration
@ConditionalOnProperty(prefix = "orthrus.ai", name = "enabled", havingValue = "true")
public class ChatClientConfig {

	@Bean
	ChatClient orchestratorChatClient(ChatModel chatModel, AiOrchestratorProperties properties) {
		ChatClient.Builder builder = ChatClient.builder(chatModel);
		String model = properties.getAi().getOrchestrator().getModel();
		if (model != null && !model.isBlank()) {
			builder.defaultOptions(ChatOptions.builder().model(model));
		}
		return builder.build();
	}

}

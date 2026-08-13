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

import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.prompt.ChatOptions;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import ch.nexsol.orthrusai.scanner.config.AiScannerProperties;

/**
 * Builds the scanner's {@link ChatClient} from whichever provider Spring AI
 * auto-configured (chosen via {@code spring.ai.model.chat}). The code depends only on the
 * provider-agnostic {@code ChatModel} and {@code ChatClient}, so switching between
 * Anthropic, OpenAI and Ollama is pure configuration. Active only when the AI agents are
 * enabled, so the module still boots without model credentials.
 */
@Configuration
@ConditionalOnProperty(prefix = "orthrus.ai", name = "enabled", havingValue = "true")
public class ChatClientConfig {

	@Bean
	ChatClient scannerChatClient(ChatModel chatModel, AiScannerProperties properties) {
		ChatClient.Builder builder = ChatClient.builder(chatModel);
		String model = properties.getAi().getScanner().getModel();
		if (model != null && !model.isBlank()) {
			builder.defaultOptions(ChatOptions.builder().model(model));
		}
		return builder.build();
	}

}

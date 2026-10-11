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
import org.springframework.ai.ollama.OllamaChatModel;
import org.springframework.ai.ollama.api.OllamaChatOptions;
import org.springframework.ai.ollama.api.ThinkOption;
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
		AiScannerProperties.Scanner scanner = properties.getAi().getScanner();
		boolean modelSet = scanner.getModel() != null && !scanner.getModel().isBlank();
		if (chatModel instanceof OllamaChatModel) {
			// Thinking models (Qwen3...) otherwise reason before every answer, and the
			// agent
			// makes one model call per tool call.
			OllamaChatOptions.Builder options = OllamaChatOptions.builder()
				.thinkOption(scanner.isThink() ? ThinkOption.ThinkBoolean.ENABLED : ThinkOption.ThinkBoolean.DISABLED);
			if (modelSet) {
				options.model(scanner.getModel());
			}
			builder.defaultOptions(options);
		}
		else if (modelSet) {
			builder.defaultOptions(ChatOptions.builder().model(scanner.getModel()));
		}
		return builder.build();
	}

}

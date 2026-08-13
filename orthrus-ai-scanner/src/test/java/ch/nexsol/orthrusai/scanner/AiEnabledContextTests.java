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

package ch.nexsol.orthrusai.scanner;

import org.junit.jupiter.api.Test;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import ch.nexsol.orthrusai.scanner.scan.EchoScanExecutor;
import ch.nexsol.orthrusai.scanner.scan.LlmScanExecutor;
import ch.nexsol.orthrusai.scanner.scan.ScanExecutor;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * With the AI agents enabled and a model on the classpath, the LLM executor replaces the
 * echo one and the agent beans wire together. A mocked ChatModel stands in for a real
 * provider so no credentials are needed.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE,
		properties = { "spring.ai.model.chat=none", "orthrus.ai.enabled=true" })
class AiEnabledContextTests {

	@MockitoBean
	private ChatModel chatModel;

	@Autowired
	private ApplicationContext context;

	@Autowired
	private ScanExecutor scanExecutor;

	@Test
	void llmExecutorReplacesEcho() {
		assertThat(this.scanExecutor).isInstanceOf(LlmScanExecutor.class);
		assertThat(this.context.getBeansOfType(EchoScanExecutor.class)).isEmpty();
	}

}

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

package ch.nexsol.orthrusai.orchestrator;

import org.junit.jupiter.api.Test;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import ch.nexsol.orthrusai.orchestrator.plan.LlmScanPlanner;
import ch.nexsol.orthrusai.orchestrator.plan.ScanPlanner;
import ch.nexsol.orthrusai.orchestrator.plan.StaticScanPlanner;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * With the LLM planner enabled and a model on the classpath, the LLM planner replaces the
 * static one and the agent beans wire together. A mocked ChatModel stands in for a real
 * provider.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE,
		properties = { "spring.ai.model.chat=none", "orthrus.ai.enabled=true" })
class AiEnabledContextTests {

	@MockitoBean
	private ChatModel chatModel;

	@Autowired
	private ApplicationContext context;

	@Autowired
	private ScanPlanner planner;

	@Test
	void llmPlannerReplacesStatic() {
		assertThat(this.planner).isInstanceOf(LlmScanPlanner.class);
		assertThat(this.context.getBeansOfType(StaticScanPlanner.class)).isEmpty();
	}

}

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

package ch.nexsol.orthrusdast.web;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.ui.ConcurrentModel;
import org.springframework.ui.Model;
import reactor.core.publisher.Mono;

import ch.nexsol.orthrusdast.web.ai.AiOrchestratorClient;
import ch.nexsol.orthrusdast.web.ai.CampaignResult;
import ch.nexsol.orthrusdast.web.ai.ScanPlan;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

/**
 * The AI campaign page reads the form body (WebFlux does not bind form fields
 * via @RequestParam), hands off to the orchestrator, and redirects to the existing scan
 * monitoring on success while surfacing errors on the form otherwise.
 */
@ExtendWith(MockitoExtension.class)
class AiCampaignControllerTest {

	@Mock
	private AiOrchestratorClient orchestratorClient;

	private AiCampaignController controller() {
		return new AiCampaignController(this.orchestratorClient);
	}

	private static MockServerWebExchange formExchange(String body) {
		return MockServerWebExchange.from(MockServerHttpRequest.post("/ai/campaign")
			.contentType(MediaType.APPLICATION_FORM_URLENCODED)
			.body(body));
	}

	@Test
	void redirectsToScansOnSuccessfulLaunch() {
		ScanPlan plan = new ScanPlan("openapi", null, 10, false, "focus");
		when(this.orchestratorClient.launchCampaign(eq("http://app.test"), any()))
			.thenReturn(Mono.just(new CampaignResult(plan, 7L, "http://app.test", "/sse/7")));

		Model model = new ConcurrentModel();
		String view = this.controller()
			.launchCampaign(formExchange("target=http://app.test&objective=find injection"), model)
			.block();

		assertThat(view).isEqualTo("redirect:/scans/all");
	}

	@Test
	void rejectsBlankTarget() {
		Model model = new ConcurrentModel();
		String view = this.controller().launchCampaign(formExchange("target=&objective=x"), model).block();

		assertThat(view).isEqualTo("ai/campaign");
		assertThat(model.getAttribute("error")).isNotNull();
	}

	@Test
	void surfacesOrchestratorErrorOnForm() {
		when(this.orchestratorClient.launchCampaign(any(), any()))
			.thenReturn(Mono.error(new RuntimeException("connection refused")));

		Model model = new ConcurrentModel();
		String view = this.controller().launchCampaign(formExchange("target=http://app.test"), model).block();

		assertThat(view).isEqualTo("ai/campaign");
		assertThat(model.getAttribute("error")).asString().contains("connection refused");
	}

	@Test
	void keepsUserOnFormWhenLaunchReturnsNoJob() {
		ScanPlan plan = new ScanPlan("openapi", null, 10, false, "focus");
		when(this.orchestratorClient.launchCampaign(any(), any()))
			.thenReturn(Mono.just(new CampaignResult(plan, null, "http://app.test", null)));

		Model model = new ConcurrentModel();
		String view = this.controller().launchCampaign(formExchange("target=http://app.test"), model).block();

		assertThat(view).isEqualTo("ai/campaign");
		assertThat(model.getAttribute("error")).isNotNull();
		assertThat(model.getAttribute("plan")).isEqualTo(plan);
	}

}

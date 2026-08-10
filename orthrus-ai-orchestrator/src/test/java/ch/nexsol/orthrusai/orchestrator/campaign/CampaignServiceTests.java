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

package ch.nexsol.orthrusai.orchestrator.campaign;

import java.util.List;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import ch.nexsol.orthrusai.orchestrator.client.OrthrusManagerClient;
import ch.nexsol.orthrusai.orchestrator.model.ScanPlan;
import ch.nexsol.orthrusai.orchestrator.plan.ScanPlanner;
import ch.nexsol.orthrusai.orchestrator.wire.ScanJobAccepted;
import ch.nexsol.orthrusai.orchestrator.wire.ScanRequest;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The campaign service must plan against the fleet's discoverers and launch the resulting
 * scan on the manager, passing the planned discoverer through.
 */
class CampaignServiceTests {

	private final OrthrusManagerClient managerClient = mock(OrthrusManagerClient.class);

	private final ScanPlanner planner = mock(ScanPlanner.class);

	private final CampaignService service = new CampaignService(this.managerClient, this.planner);

	@Test
	void plansAgainstFleetThenLaunches() {
		when(this.managerClient.getDiscoverers()).thenReturn(Mono.just(List.of("openapi", "blackbox")));
		ScanPlan plan = new ScanPlan("openapi", List.of("INJECTION"), 8, true, "focus on the API");
		when(this.planner.plan(eq("http://app.test"), eq("find injection"), eq(List.of("openapi", "blackbox"))))
			.thenReturn(plan);
		when(this.managerClient.launchScan(any()))
			.thenReturn(Mono.just(new ScanJobAccepted(99L, "http://app.test", "PENDING", "/sse/99")));

		StepVerifier.create(this.service.runCampaign("http://app.test", "find injection")).assertNext((result) -> {
			org.assertj.core.api.Assertions.assertThat(result.jobId()).isEqualTo(99L);
			org.assertj.core.api.Assertions.assertThat(result.plan()).isEqualTo(plan);
			org.assertj.core.api.Assertions.assertThat(result.eventStreamUrl()).isEqualTo("/sse/99");
		}).verifyComplete();

		verify(this.planner).plan("http://app.test", "find injection", List.of("openapi", "blackbox"));
	}

	@Test
	void launchesTheDiscovererFromThePlan() {
		when(this.managerClient.getDiscoverers()).thenReturn(Mono.just(List.of("openapi")));
		when(this.planner.plan(any(), any(), any()))
			.thenReturn(new ScanPlan("openapi", List.of(), 10, false, "default"));
		when(this.managerClient.launchScan(any()))
			.thenReturn(Mono.just(new ScanJobAccepted(1L, "t", "PENDING", "/sse/1")));

		this.service.runCampaign("http://app.test", null).block();

		org.mockito.ArgumentCaptor<ScanRequest> captor = org.mockito.ArgumentCaptor.forClass(ScanRequest.class);
		verify(this.managerClient).launchScan(captor.capture());
		org.assertj.core.api.Assertions.assertThat(captor.getValue().discovererId()).isEqualTo("openapi");
		org.assertj.core.api.Assertions.assertThat(captor.getValue().target()).isEqualTo("http://app.test");
	}

}

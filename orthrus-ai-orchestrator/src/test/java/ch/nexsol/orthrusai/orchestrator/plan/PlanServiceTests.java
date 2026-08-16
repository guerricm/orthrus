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

package ch.nexsol.orthrusai.orchestrator.plan;

import java.util.List;

import org.junit.jupiter.api.Test;
import reactor.test.StepVerifier;

import ch.nexsol.orthrusai.orchestrator.model.ScanPlan;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The plan service delegates to the planner, passing the caller's discoverers through.
 */
class PlanServiceTests {

	private final ScanPlanner planner = mock(ScanPlanner.class);

	private final PlanService service = new PlanService(this.planner);

	@Test
	void delegatesToPlannerWithDiscoverers() {
		ScanPlan plan = new ScanPlan("openapi", List.of("INJECTION"), 10, false, "focus");
		when(this.planner.plan(eq("http://app.test"), eq("find injection"), eq(List.of("openapi", "blackbox"))))
			.thenReturn(plan);

		StepVerifier.create(this.service.plan("http://app.test", "find injection", List.of("openapi", "blackbox")))
			.expectNext(plan)
			.verifyComplete();
	}

	@Test
	void toleratesNullDiscoverers() {
		ScanPlan plan = new ScanPlan("blackbox", List.of(), 10, false, "default");
		when(this.planner.plan(eq("http://app.test"), eq(null), eq(List.of()))).thenReturn(plan);

		StepVerifier.create(this.service.plan("http://app.test", null, null)).expectNext(plan).verifyComplete();
	}

}

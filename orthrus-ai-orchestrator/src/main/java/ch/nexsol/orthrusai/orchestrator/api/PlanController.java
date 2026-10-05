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

package ch.nexsol.orthrusai.orchestrator.api;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import ch.nexsol.orthrus.protocol.ai.PlanRequest;
import ch.nexsol.orthrus.protocol.ai.ScanPlan;
import ch.nexsol.orthrusai.orchestrator.plan.PlanService;

/**
 * The orchestrator's single entry point: given a target and an objective (plus the
 * caller's available discoverers), it returns a scan plan. It does not launch anything —
 * the caller applies the plan and runs it through its own flow.
 */
@RestController
@RequestMapping("/api/v1/plan")
public class PlanController {

	private final PlanService planService;

	public PlanController(PlanService planService) {
		this.planService = planService;
	}

	@PostMapping
	public Mono<ResponseEntity<ScanPlan>> plan(@RequestBody PlanRequest request) {
		if (request.target() == null || request.target().isBlank()) {
			return Mono.just(ResponseEntity.badRequest().build());
		}
		return this.planService.plan(request.target(), request.objective(), request.availableDiscoverers())
			.map(ResponseEntity::ok);
	}

}

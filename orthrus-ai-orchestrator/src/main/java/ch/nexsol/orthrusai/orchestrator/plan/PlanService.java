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

import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import ch.nexsol.orthrusai.orchestrator.model.ScanPlan;

/**
 * Produces a scan plan for a target. The orchestrator only plans; it never launches — the
 * caller (the manager UI) applies the plan and runs it. Planning may block (the LLM
 * tool-calling loop), so it runs on a bounded-elastic worker.
 */
@Service
public class PlanService {

	private final ScanPlanner planner;

	public PlanService(ScanPlanner planner) {
		this.planner = planner;
	}

	/**
	 * Plans a scan for a target.
	 * @param target the target to scan
	 * @param objective the operator's objective (may be null)
	 * @param availableDiscoverers the discoverers the caller's fleet offers
	 * @return the plan
	 */
	public Mono<ScanPlan> plan(String target, String objective, List<String> availableDiscoverers) {
		List<String> discoverers = (availableDiscoverers != null) ? availableDiscoverers : List.of();
		return Mono.fromCallable(() -> this.planner.plan(target, objective, discoverers))
			.subscribeOn(Schedulers.boundedElastic());
	}

}

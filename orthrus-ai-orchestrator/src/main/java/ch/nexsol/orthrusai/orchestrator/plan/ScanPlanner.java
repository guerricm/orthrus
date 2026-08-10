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

import ch.nexsol.orthrusai.orchestrator.model.ScanPlan;

/**
 * Produces a campaign plan for a target. The static implementation gives a sensible
 * default so the module runs without an LLM; the LLM implementation reasons about the
 * target when enabled.
 */
public interface ScanPlanner {

	/**
	 * Plans a scan campaign.
	 * @param target the target to scan
	 * @param objective the operator's objective in natural language (may be null)
	 * @param availableDiscoverers the discoverers the manager fleet offers
	 * @return the plan
	 */
	ScanPlan plan(String target, String objective, List<String> availableDiscoverers);

}

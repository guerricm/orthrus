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

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import ch.nexsol.orthrusai.orchestrator.model.ScanPlan;

/**
 * Default planner used while the LLM is disabled: a broad plan that scans everything with
 * the first available discoverer. Lets the module launch scans end-to-end without any
 * model credentials.
 */
@Component
@ConditionalOnProperty(prefix = "orthrus.ai", name = "enabled", havingValue = "false", matchIfMissing = true)
public class StaticScanPlanner implements ScanPlanner {

	private static final List<String> ALL_FAMILIES = List.of("INJECTION", "XSS", "AUTHENTICATION", "CONFIGURATION",
			"LOGIC", "MISC");

	@Override
	public ScanPlan plan(String target, String objective, List<String> availableDiscoverers) {
		String discoverer = availableDiscoverers.isEmpty() ? "blackbox" : availableDiscoverers.get(0);
		return new ScanPlan(discoverer, ALL_FAMILIES, 10, false,
				"Default plan: full scan with discoverer '" + discoverer + "' (LLM planning disabled).");
	}

}

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

package ch.nexsol.orthrusai.orchestrator.model;

import java.util.List;

/**
 * The campaign plan the orchestrator produces for a target. It is the LLM's structured
 * output: the discoverer to use, the scanner families to prioritise, and the reasoning
 * behind the choice. The campaign service turns this into a concrete scan request for the
 * manager.
 *
 * @param recommendedDiscoverer the discoverer id to use (e.g. openapi, blackbox)
 * @param prioritizedFamilies the scanner families to focus on, most important first
 * @param concurrency suggested per-scan concurrency
 * @param includePassed whether passed attempts should be kept in the result
 * @param rationale a short explanation of the plan
 */
public record ScanPlan(String recommendedDiscoverer, List<String> prioritizedFamilies, Integer concurrency,
		Boolean includePassed, String rationale) {
}

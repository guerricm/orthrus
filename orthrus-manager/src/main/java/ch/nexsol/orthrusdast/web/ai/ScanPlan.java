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

package ch.nexsol.orthrusdast.web.ai;

import java.util.List;

/**
 * The plan returned by the AI orchestrator. Local copy of the orchestrator's payload so
 * the manager stays decoupled from the optional AI module (integration is over HTTP
 * only).
 *
 * @param recommendedDiscoverer the discoverer the orchestrator chose
 * @param prioritizedFamilies the scanner families it prioritised
 * @param concurrency the suggested concurrency
 * @param includePassed whether passed attempts are kept
 * @param rationale the orchestrator's explanation
 */
public record ScanPlan(String recommendedDiscoverer, List<String> prioritizedFamilies, Integer concurrency,
		Boolean includePassed, String rationale) {
}

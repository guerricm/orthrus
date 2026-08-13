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

/**
 * The AI orchestrator's response to a campaign request. Local copy of the orchestrator's
 * payload.
 *
 * @param plan the plan produced for the target
 * @param jobId the manager job the orchestrator launched, or null if the launch failed
 * @param target the target scanned
 * @param eventStreamUrl the SSE URL to follow the job, or null
 */
public record CampaignResult(ScanPlan plan, Long jobId, String target, String eventStreamUrl) {
}

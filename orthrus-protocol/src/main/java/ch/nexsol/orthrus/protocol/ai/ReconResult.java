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

package ch.nexsol.orthrus.protocol.ai;

import java.util.List;

/**
 * The orchestrator's shared recon of a target. The manager persists it on the AI job and
 * forwards it to each scan task, so every scanner node works from the same picture
 * instead of re-probing blindly.
 *
 * @param baseUrl the base URL the endpoints resolve against
 * @param endpoints the endpoints to scan (never empty; falls back to the target itself)
 * @param context a short natural-language fingerprint of the target
 */
public record ReconResult(String baseUrl, List<Endpoint> endpoints, String context) {
}

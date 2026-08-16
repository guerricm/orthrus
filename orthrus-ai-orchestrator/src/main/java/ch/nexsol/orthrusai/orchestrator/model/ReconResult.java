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
 * The orchestrator's shared recon: it fingerprints the target once and maps its
 * endpoints, so every scanner node works from the same picture instead of re-probing
 * blindly. The manager persists it on the job and passes it to each scan task.
 *
 * @param baseUrl the base URL the endpoints resolve against (honouring the OpenAPI
 * {@code servers} block)
 * @param endpoints the endpoints to scan (never empty; falls back to the target itself)
 * @param context a short natural-language fingerprint (status, technology headers) the
 * scanner agents can use as prior knowledge
 */
public record ReconResult(String baseUrl, List<Endpoint> endpoints, String context) {
}

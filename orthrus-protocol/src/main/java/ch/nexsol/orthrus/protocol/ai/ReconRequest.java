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
 * The manager asking the orchestrator to fingerprint a target and map its endpoints.
 *
 * @param target the target to recon (an app root or an OpenAPI document)
 * @param openapiOverrideHost the base host to force on discovered endpoints, or blank
 * @param credentials credentials to send while reconning a protected target
 */
public record ReconRequest(String target, String openapiOverrideHost, List<Credential> credentials) {
}

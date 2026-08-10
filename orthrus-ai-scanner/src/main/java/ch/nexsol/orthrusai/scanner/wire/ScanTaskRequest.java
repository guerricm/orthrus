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

package ch.nexsol.orthrusai.scanner.wire;

/**
 * Task the manager dispatches to a slave. Local copy of the manager's dispatch payload so
 * this module stays independent of the other orthrus modules.
 *
 * @param taskId the task identifier used for callbacks
 * @param jobId the parent job
 * @param phase the scanner family name to run (e.g. INJECTION)
 * @param discovererId the discoverer to use for endpoint discovery
 * @param target the target under test
 * @param scanConfigurationJson the serialized scan configuration
 */
public record ScanTaskRequest(Long taskId, Long jobId, String phase, String discovererId, String target,
		String scanConfigurationJson) {
}

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

package ch.nexsol.orthrus.protocol.node;

/**
 * A scan task the manager dispatches to a node: one scanner family of one job.
 *
 * @param taskId the task to report progress against
 * @param jobId the job the task belongs to
 * @param phase the scanner family to run
 * @param discovererId the discoverer to map the target with
 * @param target the target URL
 * @param scanConfigurationJson the job's serialized scan configuration
 * @param aiContextJson the manager's serialized AI scan context, null for deterministic
 * runs
 */
public record ScanTaskRequest(Long taskId, Long jobId, String phase, String discovererId, String target,
		String scanConfigurationJson, String aiContextJson) {
}

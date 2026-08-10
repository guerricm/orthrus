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
 * Registration payload sent to the manager. The manager substring-matches a task's phase
 * against {@code capabilities}, so this flat string must contain the scanner-family names
 * this node claims.
 *
 * @param id this node's stable id
 * @param url the URL the manager should dispatch tasks to
 * @param capabilities comma-joined capability tokens (family names this node runs)
 */
public record SlaveRegistration(String id, String url, String capabilities) {
}

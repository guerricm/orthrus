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

package ch.nexsol.orthrusai.scanner.scan;

import reactor.core.publisher.Flux;

import ch.nexsol.orthrusai.scanner.wire.ScanAttempt;
import ch.nexsol.orthrusai.scanner.wire.ScanTaskRequest;

/**
 * Executes a dispatched scan task and streams the attempts it produces. The echo
 * implementation proves the manager integration without an LLM; the AI implementation
 * replaces it once {@code orthrus.ai.enabled} is on.
 */
public interface ScanExecutor {

	/**
	 * Runs the task and streams the attempts as they are produced.
	 * @param request the dispatched task
	 * @return a stream of attempts for the task
	 */
	Flux<ScanAttempt> execute(ScanTaskRequest request);

}

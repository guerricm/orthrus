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

import java.util.List;
import java.util.UUID;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;

import ch.nexsol.orthrusai.scanner.wire.ScanAttempt;
import ch.nexsol.orthrusai.scanner.wire.ScanTaskRequest;
import ch.nexsol.orthrusai.scanner.wire.Vulnerability;

/**
 * Deterministic executor used until the LLM agents are enabled. It emits a single
 * informational attempt so the full manager round-trip (dispatch, attempts, complete) can
 * be exercised in integration tests without any model credentials. Active while
 * {@code orthrus.ai.enabled} is false; the LLM executor takes over when it is true.
 */
@Component
@ConditionalOnProperty(prefix = "orthrus.ai", name = "enabled", havingValue = "false", matchIfMissing = true)
public class EchoScanExecutor implements ScanExecutor {

	@Override
	public Flux<ScanAttempt> execute(ScanTaskRequest request) {
		String scannerId = "ai-echo-" + request.phase().toLowerCase();
		Vulnerability marker = new Vulnerability(UUID.randomUUID().toString(),
				"AI scanner reachable (" + request.phase() + ")",
				"Echo executor confirming the AI scanner node received and ran the dispatched task.", "INFO", "LOW",
				scannerId, request.target(), "GET", null, List.of(), List.of(), 0.0,
				"Task " + request.taskId() + " of job " + request.jobId() + " was routed to the AI scanner node.",
				"No action required; this is a wiring probe.", "N/A", "N/A", "Diagnostic", "None");

		ScanAttempt attempt = new ScanAttempt(scannerId, "AI Echo Scanner (" + request.phase() + ")", "GET",
				request.target(), "FAILED", List.of(marker));
		return Flux.just(attempt);
	}

}

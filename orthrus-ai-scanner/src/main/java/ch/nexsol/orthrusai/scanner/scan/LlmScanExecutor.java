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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.scheduler.Schedulers;

import ch.nexsol.orthrusai.scanner.ai.FamilyAgent;
import ch.nexsol.orthrusai.scanner.recon.DiscoveredEndpoint;
import ch.nexsol.orthrusai.scanner.recon.ReconService;
import ch.nexsol.orthrusai.scanner.wire.ScanAttempt;
import ch.nexsol.orthrusai.scanner.wire.ScanTaskRequest;
import ch.nexsol.orthrusai.scanner.wire.Vulnerability;

/**
 * The AI executor: recon the target, then run the task's family agent against each
 * discovered endpoint. Each endpoint's agent runs on a bounded-elastic worker (the LLM
 * tool-calling loop is blocking), and produces one {@link ScanAttempt}. Active only when
 * {@code orthrus.ai.enabled} is true, replacing the echo executor.
 */
@Component
@ConditionalOnProperty(prefix = "orthrus.ai", name = "enabled", havingValue = "true")
public class LlmScanExecutor implements ScanExecutor {

	private static final Logger log = LoggerFactory.getLogger(LlmScanExecutor.class);

	private static final int ENDPOINT_CONCURRENCY = 3;

	private final ReconService reconService;

	private final FamilyAgent familyAgent;

	public LlmScanExecutor(ReconService reconService, FamilyAgent familyAgent) {
		this.reconService = reconService;
		this.familyAgent = familyAgent;
	}

	@Override
	public Flux<ScanAttempt> execute(ScanTaskRequest request) {
		String family = request.phase();
		return this.reconService.discover(request.target()).flatMapMany((endpoints) -> {
			log.info("AI task {} ({}): probing {} endpoint(s)", request.taskId(), family, endpoints.size());
			return Flux.fromIterable(endpoints)
				.flatMap((endpoint) -> scanEndpoint(family, endpoint), ENDPOINT_CONCURRENCY);
		});
	}

	private Flux<ScanAttempt> scanEndpoint(String family, DiscoveredEndpoint endpoint) {
		return Flux.defer(() -> {
			List<Vulnerability> findings = this.familyAgent.scan(family, endpoint);
			String scannerId = "ai-" + family.toLowerCase();
			String status = findings.isEmpty() ? "PASSED" : "FAILED";
			ScanAttempt attempt = new ScanAttempt(scannerId, "AI " + family + " Agent", endpoint.method(),
					endpoint.url(), status, findings);
			return Flux.just(attempt);
		}).subscribeOn(Schedulers.boundedElastic());
	}

}

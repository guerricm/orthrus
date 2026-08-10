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

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import ch.nexsol.orthrusai.scanner.ai.FamilyAgent;
import ch.nexsol.orthrusai.scanner.recon.DiscoveredEndpoint;
import ch.nexsol.orthrusai.scanner.recon.ReconService;
import ch.nexsol.orthrusai.scanner.wire.ScanAttempt;
import ch.nexsol.orthrusai.scanner.wire.Vulnerability;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The executor maps each discovered endpoint to one attempt, marking it FAILED when the
 * agent confirmed a finding and PASSED otherwise. The agent and recon are mocked, so no
 * LLM is involved.
 */
class LlmScanExecutorTests {

	private final ReconService reconService = mock(ReconService.class);

	private final FamilyAgent familyAgent = mock(FamilyAgent.class);

	private final LlmScanExecutor executor = new LlmScanExecutor(this.reconService, this.familyAgent);

	@Test
	void mapsFindingsToAttemptStatuses() {
		DiscoveredEndpoint vulnerable = new DiscoveredEndpoint("http://app.test/api/users/1", "GET");
		DiscoveredEndpoint clean = new DiscoveredEndpoint("http://app.test/api/health", "GET");
		when(this.reconService.discover("http://app.test")).thenReturn(Mono.just(List.of(vulnerable, clean)));

		Vulnerability finding = new Vulnerability("id", "SQLi", "desc", "CRITICAL", "HIGH", "ai-injection",
				vulnerable.url(), "GET", null, List.of(), List.of(), null, "evidence", "fix", "req", null, "vec",
				"impact");
		when(this.familyAgent.scan(eq("INJECTION"), eq(vulnerable))).thenReturn(List.of(finding));
		when(this.familyAgent.scan(eq("INJECTION"), eq(clean))).thenReturn(List.of());

		var task = new ch.nexsol.orthrusai.scanner.wire.ScanTaskRequest(1L, 1L, "INJECTION", "openapi",
				"http://app.test", "{}");

		List<ScanAttempt> attempts = this.executor.execute(task).collectList().block();

		assertThat(attempts).hasSize(2);
		ScanAttempt failed = attempts.stream()
			.filter((a) -> a.operationUrl().equals(vulnerable.url()))
			.findFirst()
			.orElseThrow();
		ScanAttempt passed = attempts.stream()
			.filter((a) -> a.operationUrl().equals(clean.url()))
			.findFirst()
			.orElseThrow();
		assertThat(failed.status()).isEqualTo("FAILED");
		assertThat(failed.vulnerabilities()).hasSize(1);
		assertThat(passed.status()).isEqualTo("PASSED");
		assertThat(passed.vulnerabilities()).isEmpty();
	}

}

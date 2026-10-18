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

import java.time.Duration;
import java.util.List;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;
import tools.jackson.databind.ObjectMapper;

import ch.nexsol.orthrus.protocol.ai.Endpoint;
import ch.nexsol.orthrus.protocol.node.AttemptStatus;
import ch.nexsol.orthrus.protocol.node.RiskLevel;
import ch.nexsol.orthrus.protocol.node.ScanAttempt;
import ch.nexsol.orthrus.protocol.node.ScanTaskRequest;
import ch.nexsol.orthrus.protocol.node.Vulnerability;
import ch.nexsol.orthrusai.scanner.ai.FamilyAgent;
import ch.nexsol.orthrusai.scanner.recon.ReconService;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The executor maps each discovered endpoint to one attempt, marking it FAILED when the
 * agent confirmed a finding and PASSED otherwise. The agent and recon are mocked, so no
 * LLM is involved.
 */
class LlmScanExecutorTests {

	private final ReconService reconService = mock(ReconService.class);

	private final FamilyAgent familyAgent = mock(FamilyAgent.class);

	private final LlmScanExecutor executor = new LlmScanExecutor(this.reconService, this.familyAgent,
			new ObjectMapper());

	@Test
	void mapsFindingsToAttemptStatuses() {
		Endpoint vulnerable = new Endpoint("GET", "http://app.test/api/users/1");
		Endpoint clean = new Endpoint("GET", "http://app.test/api/health");
		when(this.reconService.discover("http://app.test")).thenReturn(Mono.just(List.of(vulnerable, clean)));

		Vulnerability finding = new Vulnerability("id", "SQLi", "desc", RiskLevel.CRITICAL,
				Vulnerability.Confidence.HIGH, "ai-injection", vulnerable.url(), "GET", null, List.of(), List.of(),
				null, "evidence", "fix", "req", null, "vec", "impact");
		when(this.familyAgent.scan(eq("INJECTION"), eq(vulnerable), any(), any())).thenReturn(List.of(finding));
		when(this.familyAgent.scan(eq("INJECTION"), eq(clean), any(), any())).thenReturn(List.of());

		var task = new ScanTaskRequest(1L, 1L, "INJECTION", "openapi", "http://app.test", "{}", null);

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
		assertThat(failed.status()).isEqualTo(AttemptStatus.FAILED);
		assertThat(failed.vulnerabilities()).hasSize(1);
		assertThat(passed.status()).isEqualTo(AttemptStatus.PASSED);
		assertThat(passed.vulnerabilities()).isEmpty();
	}

	@Test
	void usesTheOrchestratorSharedReconWhenPresentInsteadOfProbingLocally() {
		String aiContext = """
				{"baseUrl":"http://app.test/api/v3","context":"HTTP 200; Server=nginx",\
				"endpoints":[{"method":"POST","url":"http://app.test/api/v3/pet"}],\
				"credentials":[{"location":"HEADER","name":"Authorization","value":"Bearer t"}],\
				"ignoreSslErrors":false,"connectTimeoutMs":5000,"readTimeoutMs":10000}""";
		when(this.familyAgent.scan(eq("XSS"), any(), eq("HTTP 200; Server=nginx"), any())).thenReturn(List.of());

		var task = new ScanTaskRequest(1L, 1L, "XSS", "openapi", "http://app.test/api/v3/openapi.json", "{}",
				aiContext);

		List<ScanAttempt> attempts = this.executor.execute(task).collectList().block();

		assertThat(attempts).hasSize(1);
		assertThat(attempts.get(0).operationUrl()).isEqualTo("http://app.test/api/v3/pet");
		// The shared recon is used verbatim; the node does not run its own recon.
		verify(this.reconService, never()).discover(any());
	}

	@Test
	void endpointsLeftWhenTheBudgetIsSpentAreReportedAsNotRun() {
		Endpoint fast = new Endpoint("GET", "http://app.test/api/fast");
		Endpoint slow = new Endpoint("GET", "http://app.test/api/slow");
		Endpoint queued = new Endpoint("GET", "http://app.test/api/queued");
		when(this.reconService.discover("http://app.test")).thenReturn(Mono.just(List.of(fast, slow, queued)));
		when(this.familyAgent.scan(eq("LOGIC"), eq(fast), any(), any())).thenReturn(List.of());
		when(this.familyAgent.scan(eq("LOGIC"), eq(slow), any(), any())).thenAnswer((invocation) -> {
			Thread.sleep(5000);
			return List.of();
		});
		when(this.familyAgent.scan(eq("LOGIC"), eq(queued), any(), any())).thenAnswer((invocation) -> {
			Thread.sleep(5000);
			return List.of();
		});
		var task = new ScanTaskRequest(1L, 1L, "LOGIC", "openapi", "http://app.test", "{}", null);

		List<ScanAttempt> attempts = this.executor.execute(task, Mono.delay(Duration.ofMillis(500)))
			.collectList()
			.block(Duration.ofSeconds(4));

		assertThat(attempts).extracting(ScanAttempt::operationUrl, ScanAttempt::status)
			.containsExactlyInAnyOrder(tuple(fast.url(), AttemptStatus.PASSED), tuple(slow.url(), AttemptStatus.ERROR),
					tuple(queued.url(), AttemptStatus.ERROR));
		assertThat(attempts).filteredOn((a) -> a.status() == AttemptStatus.ERROR)
			.allSatisfy((a) -> assertThat(a.scannerName()).contains("not run").contains("budget"));
	}

	@Test
	void aReconStillRunningWhenTheBudgetIsSpentYieldsNoEndpoint() {
		Endpoint late = new Endpoint("GET", "http://app.test/api/late");
		when(this.reconService.discover("http://app.test"))
			.thenReturn(Mono.delay(Duration.ofSeconds(10)).thenReturn(List.of(late)));
		var task = new ScanTaskRequest(1L, 1L, "LOGIC", "openapi", "http://app.test", "{}", null);

		List<ScanAttempt> attempts = this.executor.execute(task, Mono.delay(Duration.ofMillis(300)))
			.collectList()
			.block(Duration.ofSeconds(4));

		assertThat(attempts).isEmpty();
		verify(this.familyAgent, never()).scan(any(), any(), any(), any());
	}

	@Test
	void aTaskFinishingWithinTheBudgetReportsNoSkippedEndpoint() {
		Endpoint only = new Endpoint("GET", "http://app.test/api/only");
		when(this.reconService.discover("http://app.test")).thenReturn(Mono.just(List.of(only)));
		when(this.familyAgent.scan(eq("LOGIC"), eq(only), any(), any())).thenReturn(List.of());
		var task = new ScanTaskRequest(1L, 1L, "LOGIC", "openapi", "http://app.test", "{}", null);

		List<ScanAttempt> attempts = this.executor.execute(task, Mono.delay(Duration.ofSeconds(30)))
			.collectList()
			.block(Duration.ofSeconds(4));

		assertThat(attempts).singleElement().extracting(ScanAttempt::status).isEqualTo(AttemptStatus.PASSED);
	}

}

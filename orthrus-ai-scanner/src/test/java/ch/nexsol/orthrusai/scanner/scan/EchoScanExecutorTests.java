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

import org.junit.jupiter.api.Test;
import reactor.test.StepVerifier;

import ch.nexsol.orthrusai.scanner.wire.ScanTaskRequest;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Characterises the echo executor: a dispatched task yields exactly one diagnostic
 * attempt whose values are valid against the manager's enums, so the wire round-trip can
 * be tested without an LLM.
 */
class EchoScanExecutorTests {

	private final EchoScanExecutor executor = new EchoScanExecutor();

	@Test
	void emitsOneDiagnosticAttempt() {
		ScanTaskRequest task = new ScanTaskRequest(42L, 7L, "INJECTION", "openapi", "http://target.example/api", "{}");

		StepVerifier.create(this.executor.execute(task)).assertNext((attempt) -> {
			assertThat(attempt.status()).isEqualTo("FAILED");
			assertThat(attempt.operationUrl()).isEqualTo("http://target.example/api");
			assertThat(attempt.vulnerabilities()).hasSize(1);
			assertThat(attempt.vulnerabilities().get(0).riskLevel()).isEqualTo("INFO");
			assertThat(attempt.vulnerabilities().get(0).confidence()).isEqualTo("LOW");
		}).verifyComplete();
	}

}

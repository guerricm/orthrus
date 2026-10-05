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

package ch.nexsol.orthrusai.scanner.api;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import ch.nexsol.orthrus.protocol.node.AttemptStatus;
import ch.nexsol.orthrus.protocol.node.ScanAttempt;
import ch.nexsol.orthrus.protocol.node.ScanTaskRequest;
import ch.nexsol.orthrusai.scanner.client.ManagerClient;
import ch.nexsol.orthrusai.scanner.config.AiScannerProperties;
import ch.nexsol.orthrusai.scanner.scan.ScanExecutor;

import static org.awaitility.Awaitility.await;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The task timeout bounds the whole task, not the gap between two attempts: an agent run
 * that keeps producing attempts must still be stopped once the budget is spent, and no
 * further endpoint may be started.
 */
class AiSlaveControllerTimeoutTests {

	private final ManagerClient managerClient = mock(ManagerClient.class);

	private final ScanTaskRequest task = new ScanTaskRequest(42L, 7L, "INJECTION", "openapi",
			"http://target.example/api", "{}", null);

	private AiSlaveController controller(ScanExecutor executor, long timeoutSeconds) {
		when(this.managerClient.sendTaskAttemptsBatch(anyLong(), any())).thenReturn(Mono.empty());
		when(this.managerClient.completeTask(anyLong(), any(), anyInt(), anyInt())).thenReturn(Mono.empty());
		when(this.managerClient.failTask(anyLong(), any())).thenReturn(Mono.empty());
		AiScannerProperties properties = new AiScannerProperties();
		properties.getAi().getBudget().setTaskTimeoutSeconds(timeoutSeconds);
		return new AiSlaveController(executor, this.managerClient, properties);
	}

	private static ScanAttempt attempt() {
		return new ScanAttempt("ai-injection", "AI INJECTION Agent", "GET", "http://target.example/api",
				AttemptStatus.PASSED, List.of());
	}

	@Test
	void aTaskThatKeepsProducingAttemptsIsStoppedOnceTheBudgetIsSpent() {
		AtomicBoolean cancelled = new AtomicBoolean();
		ScanExecutor endless = (request) -> Flux.interval(Duration.ofMillis(200))
			.map((tick) -> attempt())
			.doOnCancel(() -> cancelled.set(true));

		controller(endless, 1).receiveScanTask(this.task).block();

		verify(this.managerClient, timeout(4000)).failTask(eq(42L), contains("timed out"));
		verify(this.managerClient, never()).completeTask(anyLong(), any(), anyInt(), anyInt());
		await().atMost(Duration.ofSeconds(2)).untilTrue(cancelled);
	}

	@Test
	void aTaskFinishingWithinTheBudgetCompletes() {
		ScanExecutor quick = (request) -> Flux.just(attempt(), attempt());

		controller(quick, 5).receiveScanTask(this.task).block();

		verify(this.managerClient, timeout(4000)).completeTask(eq(42L), any(), eq(2), eq(0));
		verify(this.managerClient, never()).failTask(anyLong(), any());
	}

}

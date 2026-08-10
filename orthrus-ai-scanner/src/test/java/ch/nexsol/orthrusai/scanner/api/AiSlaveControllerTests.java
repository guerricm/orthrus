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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

import ch.nexsol.orthrusai.scanner.client.ManagerClient;
import ch.nexsol.orthrusai.scanner.wire.ScanTaskRequest;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Verifies the slave endpoint acknowledges a task immediately (202) and then drives the
 * manager callbacks: at least one attempts batch followed by task completion. The manager
 * is a mock, so the test asserts the wire behaviour without a running manager.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
		properties = { "spring.ai.model.chat=none", "orthrus.ai.enabled=false" })
class AiSlaveControllerTests {

	@LocalServerPort
	private int port;

	@MockitoBean
	private ManagerClient managerClient;

	private WebTestClient client;

	@BeforeEach
	void setUp() {
		this.client = WebTestClient.bindToServer().baseUrl("http://localhost:" + this.port).build();
	}

	@Test
	void acceptsTaskAndDrivesManagerCallbacks() {
		when(this.managerClient.sendTaskAttemptsBatch(eq(42L), any())).thenReturn(Mono.empty());
		when(this.managerClient.completeTask(eq(42L), any(), anyInt(), anyInt())).thenReturn(Mono.empty());

		ScanTaskRequest task = new ScanTaskRequest(42L, 7L, "INJECTION", "openapi", "http://target.example/api", "{}");

		this.client.post()
			.uri("/api/v1/slave/tasks")
			.contentType(MediaType.APPLICATION_JSON)
			.bodyValue(task)
			.exchange()
			.expectStatus()
			.isAccepted();

		verify(this.managerClient, timeout(10000)).sendTaskAttemptsBatch(eq(42L), any());
		verify(this.managerClient, timeout(10000)).completeTask(eq(42L), any(), anyInt(), anyInt());
	}

	@Test
	void unknownTaskCancellationReturnsNotFound() {
		this.client.delete().uri("/api/v1/slave/tasks/9999").exchange().expectStatus().isNotFound();
	}

}

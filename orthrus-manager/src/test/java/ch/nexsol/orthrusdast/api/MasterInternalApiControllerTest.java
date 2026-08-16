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

package ch.nexsol.orthrusdast.api;

import java.time.Instant;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import ch.nexsol.orthrusdast.engine.JobOrchestratorService;
import ch.nexsol.orthrusdast.engine.ScanResultService;
import ch.nexsol.orthrusdast.entity.SlaveNodeEntity;
import ch.nexsol.orthrusdast.model.NodeStatus;
import ch.nexsol.orthrusdast.repository.ScanJobRepository;
import ch.nexsol.orthrusdast.repository.ScanTaskRepository;
import ch.nexsol.orthrusdast.repository.SlaveNodeRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Covers the endpoints workers call. Registration in particular has to tolerate being
 * invoked twice at once: a worker registers on startup and re-registers whenever a
 * heartbeat is rejected, and those two can overlap.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class MasterInternalApiControllerTest {

	private static final String NODE_ID = "node-a";

	@Mock
	private SlaveNodeRepository slaveNodeRepository;

	@Mock
	private ScanJobRepository scanJobRepository;

	@Mock
	private ScanResultService scanResultService;

	@Mock
	private JobOrchestratorService jobOrchestratorService;

	@Mock
	private ScanTaskRepository scanTaskRepository;

	private MasterInternalApiController controller;

	@BeforeEach
	void setUp() {
		this.controller = new MasterInternalApiController(this.slaveNodeRepository, this.scanJobRepository,
				this.scanResultService, this.jobOrchestratorService, this.scanTaskRepository);

		when(this.jobOrchestratorService.recoverTasksOfSlave(anyString(), anyString())).thenReturn(Mono.empty());
		when(this.slaveNodeRepository.insertSlaveNode(anyString(), anyString(), any(), anyString(), any()))
			.thenReturn(Mono.empty());
	}

	@Test
	void aKnownNodeIsUpdatedRatherThanInserted() {
		givenUpdateAffects(1);

		StepVerifier.create(this.controller.registerSlave(registration()))
			.assertNext((response) -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK))
			.verifyComplete();

		verify(this.slaveNodeRepository, never()).insertSlaveNode(anyString(), anyString(), any(), anyString(), any());
		verify(this.jobOrchestratorService).recoverTasksOfSlave(eq(NODE_ID), anyString());
	}

	@Test
	void anUnknownNodeIsInserted() {
		givenUpdateAffects(0);

		StepVerifier.create(this.controller.registerSlave(registration()))
			.assertNext((response) -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK))
			.verifyComplete();

		verify(this.slaveNodeRepository).insertSlaveNode(eq(NODE_ID), anyString(), any(), anyString(), any());
	}

	@Test
	void aRegistrationThatLosesTheInsertRaceStillSucceeds() {
		// Both the startup registration and the one triggered by a rejected heartbeat see
		// no row, so both insert; the loser must not surface a 500 to the worker.
		givenUpdateAffects(0);
		when(this.slaveNodeRepository.insertSlaveNode(anyString(), anyString(), any(), anyString(), any()))
			.thenReturn(Mono.error(new DuplicateKeyException("duplicate key value violates unique constraint")));

		StepVerifier.create(this.controller.registerSlave(registration()))
			.assertNext((response) -> assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK))
			.verifyComplete();
	}

	@Test
	void aHeartbeatFromAnUnknownNodeIsRejectedSoTheWorkerReRegisters() {
		when(this.slaveNodeRepository.findById(NODE_ID)).thenReturn(Mono.empty());

		ResponseEntity<Void> response = this.controller.slaveHeartbeat(NODE_ID, 0, null).block();

		assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
	}

	@Test
	void aHeartbeatMarksTheNodeBusyOnceItReachesItsQuota() {
		SlaveNodeEntity node = new SlaveNodeEntity(NODE_ID, "http://node-a:8081", NodeStatus.IDLE, "openapi");
		node.setMaxConcurrentScans(4);
		when(this.slaveNodeRepository.findById(NODE_ID)).thenReturn(Mono.just(node));
		when(this.slaveNodeRepository.updateSlaveNodeStatusAndLastSeenAt(anyString(), anyString(), any()))
			.thenReturn(Mono.just(1));

		this.controller.slaveHeartbeat(NODE_ID, 4, null).block();

		verify(this.slaveNodeRepository).updateSlaveNodeStatusAndLastSeenAt(eq(NODE_ID), eq(NodeStatus.BUSY.name()),
				any(Instant.class));
	}

	private void givenUpdateAffects(int rows) {
		when(this.slaveNodeRepository.updateSlaveNodeUrlStatusCapabilitiesAndLastSeenAt(anyString(), anyString(),
				anyString(), anyString(), any()))
			.thenReturn(Mono.just(rows));
		when(this.slaveNodeRepository.findById(NODE_ID)).thenReturn(
				(rows > 0) ? Mono.just(new SlaveNodeEntity(NODE_ID, "http://node-a:8081", NodeStatus.IDLE, "openapi"))
						: Mono.empty());
	}

	private MasterInternalApiController.SlaveRegistrationRequest registration() {
		return new MasterInternalApiController.SlaveRegistrationRequest(NODE_ID, "http://node-a:8081",
				"openapi,INJECTION");
	}

}

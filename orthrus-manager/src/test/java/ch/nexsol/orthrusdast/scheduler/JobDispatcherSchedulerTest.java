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

package ch.nexsol.orthrusdast.scheduler;

import java.time.Instant;
import java.util.concurrent.TimeUnit;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import ch.nexsol.orthrusdast.config.OrthrusProperties;
import ch.nexsol.orthrusdast.engine.JobOrchestratorService;
import ch.nexsol.orthrusdast.entity.ScanJobEntity;
import ch.nexsol.orthrusdast.entity.ScanTaskEntity;
import ch.nexsol.orthrusdast.entity.SlaveNodeEntity;
import ch.nexsol.orthrusdast.model.JobStatus;
import ch.nexsol.orthrusdast.model.NodeStatus;
import ch.nexsol.orthrusdast.repository.ScanJobRepository;
import ch.nexsol.orthrusdast.repository.ScanTaskRepository;
import ch.nexsol.orthrusdast.repository.SlaveNodeRepository;
import ch.nexsol.orthrusdast.scanner.ScannerFamily;
import ch.nexsol.orthrusdast.sse.JobEventPublisher;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Covers how work is placed on the fleet: which node is picked, when a task is left
 * waiting, and that a task is handed to a worker exactly once.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class JobDispatcherSchedulerTest {

	private static final long JOB_ID = 7L;

	@Mock
	private ScanJobRepository scanJobRepository;

	@Mock
	private ScanTaskRepository scanTaskRepository;

	@Mock
	private SlaveNodeRepository slaveNodeRepository;

	@Mock
	private JobEventPublisher jobEventPublisher;

	@Mock
	private JobOrchestratorService jobOrchestratorService;

	private MockWebServer worker;

	private JobDispatcherScheduler dispatcher;

	@BeforeEach
	void setUp() throws Exception {
		this.worker = new MockWebServer();
		this.worker.start();

		this.dispatcher = new JobDispatcherScheduler(this.scanJobRepository, this.scanTaskRepository,
				this.slaveNodeRepository, new OrthrusProperties(), this.jobEventPublisher, this.jobOrchestratorService,
				WebClient.builder());

		when(this.jobOrchestratorService.processPendingJobs()).thenReturn(Mono.empty());
		when(this.scanJobRepository.findById(JOB_ID)).thenReturn(Mono.just(job()));
		when(this.scanJobRepository.assignSlave(anyLong(), anyString())).thenReturn(Mono.just(1));
		when(this.scanTaskRepository.findByScanJobId(JOB_ID)).thenReturn(Flux.empty());
		when(this.scanTaskRepository.countByAssignedSlaveIdAndStatus(anyString(), any(JobStatus.class)))
			.thenReturn(Mono.just(0L));
		when(this.scanTaskRepository.save(any(ScanTaskEntity.class)))
			.thenAnswer((invocation) -> Mono.just(invocation.getArgument(0)));
		when(this.scanTaskRepository.claimForDispatch(anyLong(), anyString(), any())).thenReturn(Mono.just(1));
	}

	@AfterEach
	void tearDown() throws Exception {
		this.worker.shutdown();
	}

	@Test
	void aPendingTaskIsSentToACapableNode() throws Exception {
		givenPendingTasks(task(1L, ScannerFamily.INJECTION));
		givenFleet(node("node-a", "openapi,INJECTION,XSS"));
		this.worker.enqueue(new MockResponse().setResponseCode(202));

		this.dispatcher.dispatchPendingJobs();

		RecordedRequest dispatched = this.worker.takeRequest(5, TimeUnit.SECONDS);
		assertThat(dispatched).as("a capable node should have received the task").isNotNull();
		assertThat(dispatched.getMethod()).isEqualTo("POST");
		assertThat(dispatched.getPath()).isEqualTo("/api/v1/slave/tasks");
		assertThat(dispatched.getBody().readUtf8()).contains("\"phase\":\"INJECTION\"");
	}

	@Test
	void aTaskNoNodeAdvertisesIsCompletedRatherThanHangingTheJob() {
		givenPendingTasks(task(1L, ScannerFamily.LOGIC));
		givenFleet(node("node-a", "openapi,INJECTION"));
		when(this.jobOrchestratorService.onTaskUnsupported(anyLong(), anyString())).thenReturn(Mono.empty());

		this.dispatcher.dispatchPendingJobs();

		verify(this.jobOrchestratorService).onTaskUnsupported(eq(1L), anyString());
		assertThat(noDispatchHappened()).isTrue();
	}

	@Test
	void aTaskWaitsWhenEveryCapableNodeIsSaturated() {
		givenPendingTasks(task(1L, ScannerFamily.INJECTION));
		givenFleet(node("node-a", "openapi,INJECTION"));
		when(this.scanTaskRepository.countByAssignedSlaveIdAndStatus("node-a", JobStatus.RUNNING))
			.thenReturn(Mono.just(10L));

		this.dispatcher.dispatchPendingJobs();

		assertThat(noDispatchHappened()).isTrue();
		verify(this.jobOrchestratorService, never()).onTaskUnsupported(anyLong(), anyString());
	}

	@Test
	void anOfflineNodeIsNeverConsidered() {
		givenPendingTasks(task(1L, ScannerFamily.INJECTION));
		SlaveNodeEntity offline = node("node-a", "openapi,INJECTION");
		offline.setStatus(NodeStatus.OFFLINE);
		givenFleet(offline);

		this.dispatcher.dispatchPendingJobs();

		assertThat(noDispatchHappened()).isTrue();
	}

	@Test
	void aStaleNodeThatStoppedHeartbeatingIsNeverConsidered() {
		givenPendingTasks(task(1L, ScannerFamily.INJECTION));
		SlaveNodeEntity stale = node("node-a", "openapi,INJECTION");
		stale.setLastSeenAt(Instant.now().minusSeconds(600));
		givenFleet(stale);

		this.dispatcher.dispatchPendingJobs();

		assertThat(noDispatchHappened()).isTrue();
	}

	@Test
	void aTaskAlreadyClaimedByAnotherCycleIsNotSentTwice() {
		givenPendingTasks(task(1L, ScannerFamily.INJECTION));
		givenFleet(node("node-a", "openapi,INJECTION"));
		// 0 rows updated: another cycle already took this task.
		when(this.scanTaskRepository.claimForDispatch(anyLong(), anyString(), any())).thenReturn(Mono.just(0));

		this.dispatcher.dispatchPendingJobs();

		assertThat(noDispatchHappened()).isTrue();
	}

	@Test
	void aTickIsSkippedWhileThePreviousCycleIsStillRunning() {
		// A cycle that never finishes.
		when(this.jobOrchestratorService.processPendingJobs()).thenReturn(Mono.never());

		this.dispatcher.dispatchPendingJobs();
		this.dispatcher.dispatchPendingJobs();
		this.dispatcher.dispatchPendingJobs();

		verify(this.jobOrchestratorService, times(1)).processPendingJobs();
		// And nothing is placed while the queued jobs are still being split.
		verify(this.scanTaskRepository, never()).findByStatus(JobStatus.PENDING);
	}

	@Test
	void aFinishedCycleReleasesTheGuardSoTheNextTickRuns() {
		givenPendingTasks();
		givenFleet();

		this.dispatcher.dispatchPendingJobs();
		this.dispatcher.dispatchPendingJobs();

		verify(this.jobOrchestratorService, times(2)).processPendingJobs();
	}

	@Test
	void tasksArePlacedOnlyAfterQueuedJobsHaveBeenSplitIntoTasks() {
		givenPendingTasks();
		givenFleet();

		this.dispatcher.dispatchPendingJobs();

		InOrder inOrder = inOrder(this.jobOrchestratorService, this.scanTaskRepository);
		inOrder.verify(this.jobOrchestratorService).processPendingJobs();
		inOrder.verify(this.scanTaskRepository).findByStatus(JobStatus.PENDING);
	}

	@Test
	void anUnreachableNodeIsMarkedOfflineAndItsTasksRecovered() {
		SlaveNodeEntity dead = node("node-a", "openapi,INJECTION");
		dead.setUrl("http://localhost:1");
		givenFleet(dead);
		when(this.slaveNodeRepository.updateSlaveNodeStatusAndLastSeenAt(anyString(), anyString(), any()))
			.thenReturn(Mono.just(1));
		when(this.jobOrchestratorService.recoverTasksOfSlave(anyString(), anyString())).thenReturn(Mono.empty());

		this.dispatcher.monitorSlavesHealth();

		verify(this.slaveNodeRepository, org.mockito.Mockito.timeout(5000)).updateSlaveNodeStatusAndLastSeenAt("node-a",
				NodeStatus.OFFLINE.name(), dead.getLastSeenAt());
		verify(this.jobOrchestratorService, org.mockito.Mockito.timeout(5000)).recoverTasksOfSlave(eq("node-a"),
				anyString());
	}

	@Test
	void aReachableNodeIsLeftAlone() {
		givenFleet(node("node-a", "openapi,INJECTION"));
		this.worker.enqueue(new MockResponse().setResponseCode(200));

		this.dispatcher.monitorSlavesHealth();

		verify(this.slaveNodeRepository, org.mockito.Mockito.after(500).never())
			.updateSlaveNodeStatusAndLastSeenAt(anyString(), anyString(), any());
	}

	@Test
	void aHealthCheckTickIsSkippedWhileThePreviousIsStillRunning() {
		SlaveNodeEntity dead = node("node-a", "openapi,INJECTION");
		dead.setUrl("http://localhost:1");
		givenFleet(dead);
		when(this.slaveNodeRepository.updateSlaveNodeStatusAndLastSeenAt(anyString(), anyString(), any()))
			.thenReturn(Mono.just(1));
		// Recovery never finishes, so the cycle stays open.
		when(this.jobOrchestratorService.recoverTasksOfSlave(anyString(), anyString())).thenReturn(Mono.never());

		this.dispatcher.monitorSlavesHealth();
		verify(this.slaveNodeRepository, org.mockito.Mockito.timeout(5000))
			.updateSlaveNodeStatusAndLastSeenAt(anyString(), anyString(), any());

		this.dispatcher.monitorSlavesHealth();
		this.dispatcher.monitorSlavesHealth();

		verify(this.slaveNodeRepository, org.mockito.Mockito.after(500).times(1))
			.updateSlaveNodeStatusAndLastSeenAt(anyString(), anyString(), any());
	}

	private boolean noDispatchHappened() {
		try {
			return this.worker.takeRequest(300, TimeUnit.MILLISECONDS) == null;
		}
		catch (InterruptedException ex) {
			Thread.currentThread().interrupt();
			throw new IllegalStateException(ex);
		}
	}

	private void givenPendingTasks(ScanTaskEntity... tasks) {
		when(this.scanTaskRepository.findByStatus(JobStatus.PENDING)).thenReturn(Flux.just(tasks));
	}

	private void givenFleet(SlaveNodeEntity... nodes) {
		when(this.slaveNodeRepository.findAll()).thenReturn(Flux.just(nodes));
	}

	private SlaveNodeEntity node(String id, String capabilities) {
		SlaveNodeEntity node = new SlaveNodeEntity(id, this.worker.url("/").toString().replaceAll("/$", ""),
				NodeStatus.IDLE, capabilities);
		node.setLastSeenAt(Instant.now());
		return node;
	}

	private ScanTaskEntity task(Long id, ScannerFamily family) {
		ScanTaskEntity task = new ScanTaskEntity();
		task.setId(id);
		task.setScanJobId(JOB_ID);
		task.setPhase(family.name());
		task.setStatus(JobStatus.PENDING);
		task.setRetryCount(0);
		return task;
	}

	private ScanJobEntity job() {
		ScanJobEntity job = new ScanJobEntity("openapi", "https://target.example", "{}", JobStatus.RUNNING, null);
		job.setId(JOB_ID);
		return job;
	}

}

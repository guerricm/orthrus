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

package ch.nexsol.orthrusdast.engine;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import ch.nexsol.orthrusdast.entity.ScanJobEntity;
import ch.nexsol.orthrusdast.entity.ScanTaskEntity;
import ch.nexsol.orthrusdast.entity.SlaveNodeEntity;
import ch.nexsol.orthrusdast.model.JobStatus;
import ch.nexsol.orthrusdast.model.NodeStatus;
import ch.nexsol.orthrusdast.model.RiskLevel;
import ch.nexsol.orthrusdast.model.ScanConfiguration;
import ch.nexsol.orthrusdast.model.ScanResult;
import ch.nexsol.orthrusdast.repository.ScanJobRepository;
import ch.nexsol.orthrusdast.repository.ScanTaskRepository;
import ch.nexsol.orthrusdast.repository.SlaveNodeRepository;
import ch.nexsol.orthrusdast.scanner.ScannerFamily;
import ch.nexsol.orthrusdast.sse.JobEvent;
import ch.nexsol.orthrusdast.sse.JobEventPublisher;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class JobOrchestratorServiceTest {

	@Mock
	private ScanJobRepository scanJobRepository;

	@Mock
	private ScanTaskRepository scanTaskRepository;

	@Mock
	private ScanResultService scanResultService;

	@Mock
	private JobEventPublisher jobEventPublisher;

	@Mock
	private SlaveNodeRepository slaveNodeRepository;

	private MockWebServer slave;

	private JobOrchestratorService orchestrator;

	private final List<ScanTaskEntity> savedTasks = new ArrayList<>();

	@BeforeEach
	void setUp() throws Exception {
		this.slave = new MockWebServer();
		this.slave.start();

		this.orchestrator = new JobOrchestratorService(this.scanJobRepository, this.scanTaskRepository,
				this.scanResultService, this.jobEventPublisher, this.slaveNodeRepository, WebClient.builder());

		when(this.scanTaskRepository.save(any(ScanTaskEntity.class))).thenAnswer((invocation) -> {
			ScanTaskEntity task = invocation.getArgument(0);
			this.savedTasks.add(task);
			return Mono.just(task);
		});
		when(this.scanJobRepository.save(any(ScanJobEntity.class)))
			.thenAnswer((invocation) -> Mono.just(invocation.getArgument(0)));
		when(this.scanJobRepository.finishJob(anyLong(), anyString(), any())).thenReturn(Mono.just(1));
	}

	@AfterEach
	void tearDown() throws Exception {
		this.slave.shutdown();
	}

	@Test
	void aPendingJobBecomesOneTaskPerScannerFamily() {
		ScanJobEntity job = job(1L, JobStatus.PENDING);
		when(this.scanJobRepository.findByStatus(JobStatus.PENDING)).thenReturn(Flux.just(job));
		when(this.scanJobRepository.claimForOrchestration(anyLong(), any())).thenReturn(Mono.just(1));
		when(this.scanJobRepository.attachResult(anyLong(), anyString())).thenReturn(Mono.just(1));
		when(this.scanResultService.createPlaceholderResult(anyString(), anyString(), any())).thenReturn(Mono.empty());

		StepVerifier.create(this.orchestrator.processPendingJobs()).verifyComplete();

		List<String> phases = this.savedTasks.stream().map(ScanTaskEntity::getPhase).sorted().toList();
		List<String> expected = Arrays.stream(ScannerFamily.values())
			.filter((family) -> family != ScannerFamily.DISCOVERY)
			.map(Enum::name)
			.sorted()
			.toList();

		assertThat(phases).isEqualTo(expected);
		assertThat(job.getStatus()).isEqualTo(JobStatus.RUNNING);
		assertThat(job.getResultId()).isNotBlank();
	}

	@Test
	void aJobAlreadyClaimedByAnotherCycleIsNotSplitTwice() {
		ScanJobEntity job = job(1L, JobStatus.PENDING);
		when(this.scanJobRepository.findByStatus(JobStatus.PENDING)).thenReturn(Flux.just(job));
		// 0 rows updated: another cycle got there first.
		when(this.scanJobRepository.claimForOrchestration(anyLong(), any())).thenReturn(Mono.just(0));

		StepVerifier.create(this.orchestrator.processPendingJobs()).verifyComplete();

		assertThat(this.savedTasks).isEmpty();
		verify(this.scanResultService, never()).createPlaceholderResult(anyString(), anyString(), any());
		verify(this.jobEventPublisher, never()).emit(anyLong(), any(JobEvent.class));
	}

	@Test
	void theResultRowExistsBeforeTheJobIsPointedAtIt() {
		ScanJobEntity job = job(1L, JobStatus.PENDING);
		when(this.scanJobRepository.findByStatus(JobStatus.PENDING)).thenReturn(Flux.just(job));
		when(this.scanJobRepository.claimForOrchestration(anyLong(), any())).thenReturn(Mono.just(1));
		when(this.scanJobRepository.attachResult(anyLong(), anyString())).thenReturn(Mono.just(1));
		when(this.scanResultService.createPlaceholderResult(anyString(), anyString(), any())).thenReturn(Mono.empty());

		StepVerifier.create(this.orchestrator.processPendingJobs()).verifyComplete();

		// scan_jobs.result_id is a foreign key onto scan_results, so the order matters.
		InOrder inOrder = inOrder(this.scanResultService, this.scanJobRepository);
		inOrder.verify(this.scanResultService).createPlaceholderResult(anyString(), anyString(), any());
		inOrder.verify(this.scanJobRepository).attachResult(anyLong(), anyString());
	}

	@Test
	void aJobStaysOpenWhileAnyOfItsTasksIsStillRunning() {
		ScanTaskEntity task = task(10L, 1L, JobStatus.RUNNING);
		when(this.scanTaskRepository.findById(10L)).thenReturn(Mono.just(task));
		when(this.scanTaskRepository.countActiveTasksForJob(1L)).thenReturn(Mono.just(3L));

		StepVerifier.create(this.orchestrator.onScanTaskComplete(10L, 5, 1)).verifyComplete();

		assertThat(task.getStatus()).isEqualTo(JobStatus.COMPLETED);
		verify(this.jobEventPublisher, never()).complete(anyLong());
	}

	@Test
	void theLastTaskClosesTheJobAndPublishesItsGrade() {
		ScanJobEntity job = job(1L, JobStatus.RUNNING);
		job.setResultId("result-1");
		ScanTaskEntity task = task(10L, 1L, JobStatus.RUNNING);

		when(this.scanTaskRepository.findById(10L)).thenReturn(Mono.just(task));
		when(this.scanTaskRepository.countActiveTasksForJob(1L)).thenReturn(Mono.just(0L));
		when(this.scanTaskRepository.countFailedTasksForJob(1L)).thenReturn(Mono.just(0L));
		when(this.scanJobRepository.findById(1L)).thenReturn(Mono.just(job));
		when(this.scanResultService.finalizeJobResult(anyString(), anyString(), any(), any(), anyInt()))
			.thenReturn(Mono.just(resultWith(RiskLevel.HIGH)));

		StepVerifier.create(this.orchestrator.onScanTaskComplete(10L, 5, 1)).verifyComplete();

		assertThat(job.getStatus()).isEqualTo(JobStatus.COMPLETED);

		ArgumentCaptor<JobEvent> event = ArgumentCaptor.forClass(JobEvent.class);
		verify(this.jobEventPublisher).emit(anyLong(), event.capture());
		assertThat(event.getValue().status()).isEqualTo("COMPLETED");
		assertThat(event.getValue().grade()).isEqualTo("D");
		verify(this.jobEventPublisher).complete(1L);
	}

	@Test
	void aJobWithAFailedTaskIsReportedAsFailed() {
		ScanJobEntity job = job(1L, JobStatus.RUNNING);
		job.setResultId("result-1");
		ScanTaskEntity task = task(10L, 1L, JobStatus.RUNNING);
		task.setRetryCount(JobOrchestratorService.MAX_TASK_ATTEMPTS);

		when(this.scanTaskRepository.findById(10L)).thenReturn(Mono.just(task));
		when(this.scanTaskRepository.countActiveTasksForJob(1L)).thenReturn(Mono.just(0L));
		when(this.scanTaskRepository.countFailedTasksForJob(1L)).thenReturn(Mono.just(1L));
		when(this.scanJobRepository.findById(1L)).thenReturn(Mono.just(job));
		when(this.scanResultService.finalizeJobResult(anyString(), anyString(), any(), any(), anyInt()))
			.thenReturn(Mono.just(resultWith()));

		StepVerifier.create(this.orchestrator.onTaskFailed(10L, "boom")).verifyComplete();

		assertThat(task.getStatus()).isEqualTo(JobStatus.FAILED);
		assertThat(job.getStatus()).isEqualTo(JobStatus.FAILED);
	}

	@Test
	void aFailedTaskIsRequeuedUntilTheAttemptBudgetIsSpent() {
		ScanTaskEntity task = task(10L, 1L, JobStatus.RUNNING);
		task.setAssignedSlaveId("slave-a");
		task.setRetryCount(0);
		when(this.scanTaskRepository.findById(10L)).thenReturn(Mono.just(task));

		StepVerifier.create(this.orchestrator.onTaskFailed(10L, "transient")).verifyComplete();

		assertThat(task.getStatus()).isEqualTo(JobStatus.PENDING);
		assertThat(task.getRetryCount()).isEqualTo(1);
		assertThat(task.getAssignedSlaveId()).isNull();
		verify(this.scanTaskRepository, never()).countActiveTasksForJob(anyLong());
	}

	@Test
	void tasksHeldByARestartedWorkerAreRequeued() {
		ScanTaskEntity task = task(10L, 1L, JobStatus.RUNNING);
		task.setAssignedSlaveId("slave-a");
		when(this.scanTaskRepository.findByAssignedSlaveIdAndStatus("slave-a", JobStatus.RUNNING))
			.thenReturn(Flux.just(task));

		StepVerifier.create(this.orchestrator.recoverTasksOfSlave("slave-a", "restarted")).verifyComplete();

		assertThat(task.getStatus()).isEqualTo(JobStatus.PENDING);
		assertThat(task.getAssignedSlaveId()).isNull();
	}

	@Test
	void cancellingAJobTellsTheWorkerToDropItsRunningTask() throws Exception {
		ScanJobEntity job = job(1L, JobStatus.RUNNING);
		ScanTaskEntity running = task(10L, 1L, JobStatus.RUNNING);
		running.setAssignedSlaveId("slave-a");
		ScanTaskEntity queued = task(11L, 1L, JobStatus.PENDING);
		ScanTaskEntity done = task(12L, 1L, JobStatus.COMPLETED);

		when(this.scanJobRepository.findById(1L)).thenReturn(Mono.just(job));
		when(this.scanJobRepository.cancelJob(anyLong(), any())).thenReturn(Mono.just(1));
		when(this.scanTaskRepository.findByScanJobId(1L)).thenReturn(Flux.just(running, queued, done));
		when(this.slaveNodeRepository.findById("slave-a")).thenReturn(Mono.just(slaveNode()));
		this.slave.enqueue(new MockResponse().setResponseCode(200));

		StepVerifier.create(this.orchestrator.cancelJob(1L)).verifyComplete();

		assertThat(job.getStatus()).isEqualTo(JobStatus.CANCELLED);
		assertThat(running.getStatus()).isEqualTo(JobStatus.CANCELLED);
		assertThat(queued.getStatus()).isEqualTo(JobStatus.CANCELLED);
		assertThat(done.getStatus()).isEqualTo(JobStatus.COMPLETED);

		RecordedRequest sentToWorker = this.slave.takeRequest();
		assertThat(sentToWorker.getMethod()).isEqualTo("DELETE");
		assertThat(sentToWorker.getPath()).isEqualTo("/api/v1/slave/tasks/10");
	}

	@Test
	void aJobIsAnnouncedOnceEvenIfTwoCyclesSeeItsLastTaskFinish() {
		ScanJobEntity job = job(1L, JobStatus.RUNNING);
		job.setResultId("result-1");
		ScanTaskEntity task = task(10L, 1L, JobStatus.RUNNING);

		when(this.scanTaskRepository.findById(10L)).thenReturn(Mono.just(task));
		when(this.scanTaskRepository.countActiveTasksForJob(1L)).thenReturn(Mono.just(0L));
		when(this.scanTaskRepository.countFailedTasksForJob(1L)).thenReturn(Mono.just(0L));
		when(this.scanJobRepository.findById(1L)).thenReturn(Mono.just(job));
		// 0 rows updated: the job was no longer RUNNING, so another cycle already closed
		// it.
		when(this.scanJobRepository.finishJob(anyLong(), anyString(), any())).thenReturn(Mono.just(0));

		StepVerifier.create(this.orchestrator.onScanTaskComplete(10L, 5, 1)).verifyComplete();

		verify(this.scanResultService, never()).finalizeJobResult(anyString(), anyString(), any(), any(), anyInt());
		verify(this.jobEventPublisher, never()).emit(anyLong(), any(JobEvent.class));
		verify(this.jobEventPublisher, never()).complete(anyLong());
	}

	@Test
	void aTaskNoNodeSupportsIsClosedOnceAndUnblocksItsJob() {
		ScanJobEntity job = job(1L, JobStatus.RUNNING);
		job.setResultId("result-1");
		ScanTaskEntity task = task(10L, 1L, JobStatus.PENDING);

		when(this.scanTaskRepository.findById(10L)).thenReturn(Mono.just(task));
		when(this.scanTaskRepository.completeUnsupported(anyLong(), any())).thenReturn(Mono.just(1));
		when(this.scanTaskRepository.countActiveTasksForJob(1L)).thenReturn(Mono.just(0L));
		when(this.scanTaskRepository.countFailedTasksForJob(1L)).thenReturn(Mono.just(0L));
		when(this.scanJobRepository.findById(1L)).thenReturn(Mono.just(job));
		when(this.scanResultService.finalizeJobResult(anyString(), anyString(), any(), any(), anyInt()))
			.thenReturn(Mono.just(resultWith()));

		StepVerifier.create(this.orchestrator.onTaskUnsupported(10L, "no capable node")).verifyComplete();

		assertThat(job.getStatus()).isEqualTo(JobStatus.COMPLETED);
		verify(this.jobEventPublisher).complete(1L);
	}

	@Test
	void anUnsupportedTaskAlreadyClosedElsewhereIsNotClosedAgain() {
		ScanTaskEntity task = task(10L, 1L, JobStatus.PENDING);
		when(this.scanTaskRepository.findById(10L)).thenReturn(Mono.just(task));
		// 0 rows updated: the task was no longer PENDING.
		when(this.scanTaskRepository.completeUnsupported(anyLong(), any())).thenReturn(Mono.just(0));

		StepVerifier.create(this.orchestrator.onTaskUnsupported(10L, "no capable node")).verifyComplete();

		verify(this.scanTaskRepository, never()).countActiveTasksForJob(anyLong());
		verify(this.jobEventPublisher, never()).emit(anyLong(), any(JobEvent.class));
	}

	@Test
	void cancellingAJobThatAlreadyFinishedDoesNothing() {
		ScanJobEntity job = job(1L, JobStatus.COMPLETED);
		when(this.scanJobRepository.findById(1L)).thenReturn(Mono.just(job));
		// 0 rows updated: the job was no longer cancellable.
		when(this.scanJobRepository.cancelJob(anyLong(), any())).thenReturn(Mono.just(0));

		StepVerifier.create(this.orchestrator.cancelJob(1L)).verifyComplete();

		verify(this.scanTaskRepository, never()).findByScanJobId(anyLong());
		verify(this.jobEventPublisher, never()).emit(anyLong(), any(JobEvent.class));
	}

	@Test
	void aCancelledJobIsNotReopenedWhenItsLastTaskReportsBack() {
		ScanJobEntity job = job(1L, JobStatus.CANCELLED);
		ScanTaskEntity task = task(10L, 1L, JobStatus.RUNNING);

		when(this.scanTaskRepository.findById(10L)).thenReturn(Mono.just(task));
		when(this.scanTaskRepository.countActiveTasksForJob(1L)).thenReturn(Mono.just(0L));
		when(this.scanJobRepository.findById(1L)).thenReturn(Mono.just(job));

		StepVerifier.create(this.orchestrator.onScanTaskComplete(10L, 1, 0)).verifyComplete();

		assertThat(job.getStatus()).isEqualTo(JobStatus.CANCELLED);
		verify(this.jobEventPublisher, never()).emit(anyLong(), any(JobEvent.class));
	}

	private ScanJobEntity job(Long id, JobStatus status) {
		ScanJobEntity job = new ScanJobEntity("openapi", "https://target.example", "{}", status, null);
		job.setId(id);
		job.setStartedAt(Instant.now());
		return job;
	}

	private ScanTaskEntity task(Long id, Long jobId, JobStatus status) {
		ScanTaskEntity task = new ScanTaskEntity();
		task.setId(id);
		task.setScanJobId(jobId);
		task.setPhase(ScannerFamily.INJECTION.name());
		task.setStatus(status);
		task.setRetryCount(0);
		return task;
	}

	private SlaveNodeEntity slaveNode() {
		return new SlaveNodeEntity("slave-a", this.slave.url("/").toString().replaceAll("/$", ""), NodeStatus.BUSY,
				"openapi,INJECTION");
	}

	private ScanResult resultWith(RiskLevel... levels) {
		Map<RiskLevel, Long> summary = new EnumMap<>(RiskLevel.class);
		for (RiskLevel level : levels) {
			summary.merge(level, 1L, Long::sum);
		}
		return new ScanResult("result-1", "https://target.example", Instant.now(), Instant.now(), 0, 0, List.of(),
				summary, Map.of(), ScanConfiguration.defaults(), List.of(), "openapi");
	}

}

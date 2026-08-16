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

package ch.nexsol.orthrusdast.web;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import tools.jackson.databind.ObjectMapper;

import ch.nexsol.orthrusdast.auth.OAuth2TokenFetcher;
import ch.nexsol.orthrusdast.entity.ScanJobEntity;
import ch.nexsol.orthrusdast.model.JobStatus;
import ch.nexsol.orthrusdast.repository.ScanJobRepository;
import ch.nexsol.orthrusdast.repository.ScanTaskRepository;
import ch.nexsol.orthrusdast.repository.SlaveNodeRepository;
import ch.nexsol.orthrusdast.sse.JobEventPublisher;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Restarting a scan must replay it the way it was run: an AI scan replays on the AI
 * nodes, a deterministic scan on the workers. The mode is otherwise silently lost when a
 * completed job is replayed through the 5-arg constructor.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SystemControllerTest {

	@Mock
	private ScanJobRepository scanJobRepository;

	@Mock
	private SlaveNodeRepository slaveNodeRepository;

	@Mock
	private ScanTaskRepository scanTaskRepository;

	@Mock
	private OAuth2TokenFetcher tokenFetcher;

	@Mock
	private JobEventPublisher jobEventPublisher;

	private SystemController controller() {
		return new SystemController(this.scanJobRepository, this.slaveNodeRepository, this.scanTaskRepository,
				this.tokenFetcher, new ObjectMapper(), this.jobEventPublisher);
	}

	private List<ScanJobEntity> captureSavedJobs() {
		List<ScanJobEntity> saved = new ArrayList<>();
		when(this.scanJobRepository.save(any(ScanJobEntity.class))).thenAnswer((invocation) -> {
			ScanJobEntity job = invocation.getArgument(0);
			job.setId(99L);
			saved.add(job);
			return Mono.just(job);
		});
		return saved;
	}

	@Test
	void restartingACompletedAiScanReplaysItAsAnAiScan() {
		ScanJobEntity job = new ScanJobEntity("openapi", "http://app.test", "{}", JobStatus.COMPLETED, 7L);
		job.setId(1L);
		job.setAiMode(true);
		when(this.scanJobRepository.findById(1L)).thenReturn(Mono.just(job));
		List<ScanJobEntity> saved = captureSavedJobs();

		StepVerifier.create(controller().restartJob(1L)).expectNext("redirect:/scans/all").verifyComplete();

		assertThat(saved).hasSize(1);
		assertThat(saved.get(0).isAiMode()).isTrue();
		assertThat(saved.get(0).getStatus()).isEqualTo(JobStatus.PENDING);
	}

	@Test
	void restartingACompletedDeterministicScanStaysDeterministic() {
		ScanJobEntity job = new ScanJobEntity("openapi", "http://app.test", "{}", JobStatus.COMPLETED, 7L);
		job.setId(2L);
		job.setAiMode(false);
		when(this.scanJobRepository.findById(2L)).thenReturn(Mono.just(job));
		List<ScanJobEntity> saved = captureSavedJobs();

		StepVerifier.create(controller().restartJob(2L)).expectNext("redirect:/scans/all").verifyComplete();

		assertThat(saved).hasSize(1);
		assertThat(saved.get(0).isAiMode()).isFalse();
	}

	@Test
	void restartingAFailedAiScanKeepsAiModeAndClearsStaleRecon() {
		ScanJobEntity job = new ScanJobEntity("openapi", "http://app.test", "{}", JobStatus.FAILED, 7L);
		job.setId(3L);
		job.setAiMode(true);
		job.setAiContext("{\"baseUrl\":\"http://app.test\",\"endpoints\":[],\"context\":\"stale\"}");
		when(this.scanJobRepository.findById(3L)).thenReturn(Mono.just(job));
		List<ScanJobEntity> saved = captureSavedJobs();

		StepVerifier.create(controller().restartJob(3L)).expectNext("redirect:/scans/all").verifyComplete();

		assertThat(saved).hasSize(1);
		assertThat(saved.get(0).isAiMode()).isTrue();
		assertThat(saved.get(0).getAiContext()).isNull();
	}

}

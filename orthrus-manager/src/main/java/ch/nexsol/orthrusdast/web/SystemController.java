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

import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.http.codec.ServerSentEvent;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import ch.nexsol.orthrusdast.entity.ScanJobEntity;
import ch.nexsol.orthrusdast.entity.SlaveNodeEntity;
import ch.nexsol.orthrusdast.model.JobStatus;
import ch.nexsol.orthrusdast.repository.ScanJobRepository;
import ch.nexsol.orthrusdast.repository.ScanTaskRepository;
import ch.nexsol.orthrusdast.repository.SlaveNodeRepository;
import ch.nexsol.orthrusdast.sse.JobEvent;
import ch.nexsol.orthrusdast.sse.JobEventPublisher;

/**
 * Administration pages: cluster overview, slave management and job replay.
 */
@Controller
public class SystemController {

	private static final Logger log = LoggerFactory.getLogger(SystemController.class);

	private final ScanJobRepository scanJobRepository;

	private final SlaveNodeRepository slaveNodeRepository;

	private final ScanTaskRepository scanTaskRepository;

	private final JobEventPublisher jobEventPublisher;

	public SystemController(ScanJobRepository scanJobRepository, SlaveNodeRepository slaveNodeRepository,
			ScanTaskRepository scanTaskRepository, JobEventPublisher jobEventPublisher) {
		this.scanJobRepository = scanJobRepository;
		this.slaveNodeRepository = slaveNodeRepository;
		this.scanTaskRepository = scanTaskRepository;
		this.jobEventPublisher = jobEventPublisher;
	}

	@GetMapping("/system")
	public Mono<String> systemStatus(Model model) {
		return Mono
			.zip(scanJobRepository.findByStatusIn(List.of(JobStatus.PENDING, JobStatus.RUNNING)).collectList(),
					slaveNodeRepository.findAll().collectList(),
					scanTaskRepository.findByStatus(JobStatus.RUNNING).collectList())
			.map((tuple) -> {
				List<ScanJobEntity> jobs = tuple.getT1();
				jobs.sort((j1, j2) -> Long.compare(j2.getId(), j1.getId()));
				List<SlaveNodeEntity> slaves = tuple.getT2();
				List<ch.nexsol.orthrusdast.entity.ScanTaskEntity> runningTasks = tuple.getT3();

				Map<String, Long> activeJobsCount = new HashMap<>();
				for (SlaveNodeEntity slave : slaves) {
					long count = runningTasks.stream()
						.filter((t) -> slave.getId().equals(t.getAssignedSlaveId()))
						.count();
					activeJobsCount.put(slave.getId(), count);
				}

				model.addAttribute("jobs", jobs);
				model.addAttribute("slaves", slaves);
				model.addAttribute("activeJobsCount", activeJobsCount);
				return "system";
			});
	}

	@PostMapping("/system/jobs/{id}/restart")
	public Mono<String> restartJob(@PathVariable Long id) {
		// The stored configuration is replayed as-is: OAuth2 tokens are issued when the
		// replay's tasks are dispatched.
		return scanJobRepository.findById(id)
			.flatMap((job) -> scanJobRepository.save(prepareReplayedJob(job)))
			.doOnNext((newJob) -> jobEventPublisher.emit(newJob.getId(),
					JobEvent.queued(newJob.getId(), newJob.getTarget())))
			.thenReturn("redirect:/scans/all");
	}

	private ScanJobEntity prepareReplayedJob(ScanJobEntity job) {
		if (job.getStatus() == JobStatus.COMPLETED) {
			ScanJobEntity replay = new ScanJobEntity(job.getDiscovererId(), job.getTarget(),
					job.getScanConfigurationJson(), JobStatus.PENDING, job.getTestPlanId());
			// Preserve how the scan was run: an AI scan must replay on the AI nodes, not
			// fall back to a deterministic run. The recon is re-fetched when the job
			// starts.
			replay.setAiMode(job.isAiMode());
			return replay;
		}
		else {
			job.setStatus(JobStatus.PENDING);
			job.setAssignedSlaveId(null);
			job.setStartedAt(null);
			job.setCompletedAt(null);
			job.setResultId(null);
			job.setVulnsCount(null);
			job.setTestsCount(null);
			// Drop the previous run's shared recon so the replay re-recons the target
			// fresh.
			job.setAiRecon(null);
			return job;
		}
	}

	@PostMapping("/system/slaves/{id}/toggle-active")
	public Mono<String> toggleSlaveActive(@PathVariable String id) {
		return slaveNodeRepository.findById(id)
			.flatMap((slave) -> slaveNodeRepository.updateSlaveNodeIsActive(id, !slave.getIsActive()))
			.thenReturn("redirect:/system");
	}

	@PostMapping("/system/slaves/{id}/concurrency")
	public Mono<String> updateSlaveConcurrency(@PathVariable String id, ServerWebExchange exchange) {
		return exchange.getFormData().flatMap((formData) -> {
			int maxConcurrentScans = WebFormUtils.parseIntOrDefault(formData.getFirst("maxConcurrentScans"), 0);
			return slaveNodeRepository.updateSlaveNodeMaxConcurrentScans(id, Math.max(0, maxConcurrentScans));
		}).thenReturn("redirect:/system");
	}

	@GetMapping(value = "/api/sse/system", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
	@ResponseBody
	public Flux<ServerSentEvent<String>> systemEvents() {
		return Flux.interval(Duration.ofSeconds(5))
			.map((seq) -> ServerSentEvent.<String>builder().event("pulse").data(String.valueOf(seq)).build());
	}

}

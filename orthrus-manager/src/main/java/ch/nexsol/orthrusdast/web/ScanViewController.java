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

import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.MediaType;
import org.springframework.http.codec.ServerSentEvent;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import tools.jackson.databind.ObjectMapper;

import ch.nexsol.orthrusdast.engine.ScanResultService;
import ch.nexsol.orthrusdast.entity.ScanJobEntity;
import ch.nexsol.orthrusdast.entity.TestPlanEntity;
import ch.nexsol.orthrusdast.model.AttemptStatus;
import ch.nexsol.orthrusdast.model.EndpointAttemptGroup;
import ch.nexsol.orthrusdast.model.JobStatus;
import ch.nexsol.orthrusdast.model.RiskLevel;
import ch.nexsol.orthrusdast.model.ScanAttempt;
import ch.nexsol.orthrusdast.model.ScanConfiguration;
import ch.nexsol.orthrusdast.model.Vulnerability;
import ch.nexsol.orthrusdast.repository.ScanJobRepository;
import ch.nexsol.orthrusdast.repository.SlaveNodeRepository;
import ch.nexsol.orthrusdast.repository.TestPlanRepository;
import ch.nexsol.orthrusdast.sse.JobEvent;
import ch.nexsol.orthrusdast.sse.JobEventPublisher;

/**
 * Scan pages: live overview, history, details and cancellation, plus the SSE streams the
 * browser subscribes to.
 */
@Controller
public class ScanViewController {

	private static final Logger log = LoggerFactory.getLogger(ScanViewController.class);

	private final ScanJobRepository scanJobRepository;

	private final ScanResultService scanResultService;

	private final TestPlanRepository testPlanRepository;

	private final SlaveNodeRepository slaveNodeRepository;

	private final JobEventPublisher jobEventPublisher;

	private final ObjectMapper objectMapper;

	private final WebClient webClient;

	public ScanViewController(ScanJobRepository scanJobRepository, ScanResultService scanResultService,
			TestPlanRepository testPlanRepository, SlaveNodeRepository slaveNodeRepository,
			JobEventPublisher jobEventPublisher, ObjectMapper objectMapper, WebClient.Builder webClientBuilder) {
		this.scanJobRepository = scanJobRepository;
		this.scanResultService = scanResultService;
		this.testPlanRepository = testPlanRepository;
		this.slaveNodeRepository = slaveNodeRepository;
		this.jobEventPublisher = jobEventPublisher;
		this.objectMapper = objectMapper;
		this.webClient = webClientBuilder.build();
	}

	@GetMapping("/scans/{id}/details")
	public Mono<String> scanDetails(@PathVariable Long id, Model model) {
		return scanJobRepository.findById(id).flatMap((job) -> {
			if (job.getResultId() != null) {
				return scanResultService.findById(job.getResultId()).flatMap((result) -> {
					model.addAttribute("scanId", job.getId());
					model.addAttribute("resultId", job.getResultId());
					model.addAttribute("targetUrl", result.targetUrl());
					model.addAttribute("discovererId", job.getDiscovererId());
					return Mono
						.fromCallable(
								() -> objectMapper.readValue(job.getScanConfigurationJson(), ScanConfiguration.class))
						.doOnNext((conf) -> model.addAttribute("config", conf))
						.onErrorResume((e) -> {
							log.warn(
									"Failed to parse configuration of job {}; falling back to the result's configuration",
									job.getId(), e);
							model.addAttribute("config", result.configuration());
							return Mono.empty();
						})
						.then(Mono.defer(() -> {
							List<Vulnerability> sortedVulns = new ArrayList<>(result.vulnerabilities());
							sortedVulns.sort((v1, v2) -> {
								int riskCompare = Integer.compare(v2.riskLevel().ordinal(), v1.riskLevel().ordinal());
								if (riskCompare != 0) {
									return riskCompare;
								}
								String cwe1 = (v1.cwe() != null) ? v1.cwe().name() : "";
								String cwe2 = (v2.cwe() != null) ? v2.cwe().name() : "";
								int cweCompare = cwe1.compareTo(cwe2);
								if (cweCompare != 0) {
									return cweCompare;
								}
								String name1 = (v1.name() != null) ? v1.name() : "";
								String name2 = (v2.name() != null) ? v2.name() : "";
								return name1.compareTo(name2);
							});
							model.addAttribute("vulnerabilities", sortedVulns);

							DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd.MM.yyyy HH:mm")
								.withZone(ZoneId.systemDefault());
							model.addAttribute("scanDate", formatter.format(result.scanStartTime()));

							long critical = result.riskSummary().getOrDefault(RiskLevel.CRITICAL, 0L);
							long high = result.riskSummary().getOrDefault(RiskLevel.HIGH, 0L);
							long medium = result.riskSummary().getOrDefault(RiskLevel.MEDIUM, 0L);
							long low = result.riskSummary().getOrDefault(RiskLevel.LOW, 0L);
							long info = result.riskSummary().getOrDefault(RiskLevel.INFO, 0L);

							model.addAttribute("totalVulns", result.vulnerabilities().size());
							model.addAttribute("countCritical", critical);
							model.addAttribute("countHigh", high);
							model.addAttribute("countMedium", medium);
							model.addAttribute("countLow", low);
							model.addAttribute("countInfo", info);
							model.addAttribute("globalGrade", computeGrade(result.riskSummary()));

							if (result.attempts() != null && !result.attempts().isEmpty()) {
								LinkedHashMap<String, List<ScanAttempt>> grouped = new LinkedHashMap<>();
								for (ScanAttempt a : result.attempts()) {
									String key = a.operationMethod() + " " + a.operationUrl();
									grouped.computeIfAbsent(key, (k) -> new ArrayList<>()).add(a);
								}

								List<EndpointAttemptGroup> attemptGroupsList = new ArrayList<>();
								for (Map.Entry<String, List<ScanAttempt>> entry : grouped.entrySet()) {
									long passed = entry.getValue()
										.stream()
										.filter((a) -> AttemptStatus.PASSED == a.status())
										.count();
									long failed = entry.getValue()
										.stream()
										.filter((a) -> AttemptStatus.FAILED == a.status())
										.count();
									long authError = entry.getValue()
										.stream()
										.filter((a) -> AttemptStatus.AUTH_ERROR == a.status())
										.count();
									long error = entry.getValue()
										.stream()
										.filter((a) -> AttemptStatus.ERROR == a.status())
										.count();
									attemptGroupsList.add(new EndpointAttemptGroup(entry.getKey(), entry.getValue(),
											passed, failed, authError, error));
								}
								model.addAttribute("attemptGroups", attemptGroupsList);
							}

							return Mono.just("scans/details");
						}));
				});
			}
			return Mono.just("redirect:/scans");
		}).switchIfEmpty(Mono.just("redirect:/scans"));
	}

	@PostMapping("/scans/{id}/cancel")
	public Mono<String> cancelScan(@PathVariable Long id) {
		return scanJobRepository.findById(id).flatMap((job) -> {
			if (job.getStatus() == JobStatus.PENDING) {
				job.setStatus(JobStatus.CANCELLED);
				return scanJobRepository.save(job)
					.doOnSuccess((j) -> jobEventPublisher.emit(j.getId(),
							JobEvent.failed(j.getId(), j.getTarget(), "Scan cancelled by user")));
			}
			else if (job.getStatus() == JobStatus.RUNNING) {
				job.setStatus(JobStatus.CANCELLED);
				return scanJobRepository.save(job)
					.doOnSuccess((j) -> jobEventPublisher.emit(j.getId(),
							JobEvent.failed(j.getId(), j.getTarget(), "Scan cancelled by user")))
					.flatMap((j) -> {
						if (job.getAssignedSlaveId() != null) {
							return slaveNodeRepository.findById(job.getAssignedSlaveId())
								.flatMap((slave) -> webClient.delete()
									.uri(slave.getUrl() + "/api/v1/slave/scans/" + id)
									.retrieve()
									.bodyToMono(Void.class)
									.onErrorResume((e) -> Mono.empty()));
						}
						return Mono.empty();
					});
			}
			return Mono.empty();
		}).thenReturn("redirect:/scans/all");
	}

	@GetMapping("/scans/all")
	public Mono<String> activeScans(Model model) {
		return scanJobRepository.findAllByOrderByCreatedAtDesc(PageRequest.of(0, 100))
			.collectList()
			.flatMap(this::populatePlanNames)
			.flatMap((history) -> {
				// Sort: PENDING first, then RUNNING, then everything else (COMPLETED,
				// FAILED),
				// and within those groups by date desc
				history.sort((a, b) -> {
					int aWeight = getStatusWeight(a.getStatus());
					int bWeight = getStatusWeight(b.getStatus());
					if (aWeight != bWeight) {
						return Integer.compare(aWeight, bWeight);
					}
					return b.getCreatedAt().compareTo(a.getCreatedAt()); // desc
				});

				return Flux.fromIterable(history).flatMapSequential((job) -> {
					Map<String, Object> map = new HashMap<>();
					map.put("job", job);
					return Mono
						.fromCallable(
								() -> objectMapper.readValue(job.getScanConfigurationJson(), ScanConfiguration.class))
						.doOnNext((conf) -> map.put("config", conf))
						.onErrorResume((e) -> {
							log.warn("Failed to parse configuration of job {}", job.getId(), e);
							return Mono.empty();
						})
						.then(Mono.defer(() -> {
							if (job.getStatus() == JobStatus.COMPLETED && job.getResultId() != null) {
								return scanResultService.findById(job.getResultId()).map((result) -> {
									map.put("result", result);
									map.put("globalGrade", computeGrade(result.riskSummary()));
									return map;
								}).defaultIfEmpty(map);
							}
							return Mono.just(map);
						}));
				}).collectList().map((mappedJobs) -> {
					model.addAttribute("activeJobs", mappedJobs);
					return "scans/all";
				});
			});
	}

	private int getStatusWeight(JobStatus status) {
		if (status == JobStatus.PENDING) {
			return 1;
		}
		if (status == JobStatus.RUNNING) {
			return 2;
		}
		return 3;
	}

	/**
	 * SSE endpoint for browsers to subscribe to live job status updates.
	 * @param id the job id
	 * @return a stream of job events
	 */
	@GetMapping(value = "/api/sse/jobs/{id}/events", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
	@ResponseBody
	public Flux<ServerSentEvent<JobEvent>> jobEvents(@PathVariable Long id) {
		return jobEventPublisher.stream(id)
			.map((event) -> ServerSentEvent.<JobEvent>builder().event("message").data(event).build());
	}

	/**
	 * SSE endpoint for browsers to subscribe to live status updates for ALL jobs.
	 * @return a stream of global job events
	 */
	@GetMapping(value = "/api/sse/jobs/events", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
	@ResponseBody
	public Flux<ServerSentEvent<JobEvent>> allJobEvents() {
		return jobEventPublisher.globalStream()
			.map((event) -> ServerSentEvent.<JobEvent>builder().event("message").data(event).build());
	}

	@GetMapping("/scans")
	public Mono<String> listScans(Model model) {
		return scanJobRepository.findAllByOrderByCreatedAtDesc(PageRequest.of(0, 10))
			.collectList()
			.flatMap(this::populatePlanNames)
			.map((history) -> {
				model.addAttribute("history", history);
				return "scans/list";
			});
	}

	@GetMapping("/api/scans")
	public Mono<String> getScansFragment(@RequestParam(defaultValue = "0") int page,
			@RequestParam(defaultValue = "10") int size, Model model) {
		return scanJobRepository.findAllByOrderByCreatedAtDesc(PageRequest.of(page, size))
			.collectList()
			.flatMap(this::populatePlanNames)
			.map((history) -> {
				model.addAttribute("history", history);
				return "fragments/scan-items :: items";
			});
	}

	@GetMapping("/api/scans/row/{id}")
	public Mono<String> getScanRowFragment(@PathVariable Long id, Model model) {
		return scanJobRepository.findById(id).flatMap((job) -> populatePlanNames(List.of(job))).map((jobs) -> {
			model.addAttribute("history", jobs);
			return "fragments/scan-items :: items";
		}).defaultIfEmpty("fragments/scan-items :: items");
	}

	@GetMapping("/api/scans/queued-row/{id}")
	public Mono<String> getScanQueuedRowFragment(@PathVariable Long id, Model model) {
		return scanJobRepository.findById(id)
			.flatMap((job) -> populatePlanNames(List.of(job)))
			.map((jobs) -> jobs.get(0))
			.flatMap((job) -> {
				model.addAttribute("jobId", job.getId());
				model.addAttribute("planName", job.getPlanName());
				model.addAttribute("target", job.getTarget());
				model.addAttribute("discovererId", job.getDiscovererId());
				model.addAttribute("createdAt", job.getCreatedAt());
				model.addAttribute("status", job.getStatus().name());
				model.addAttribute("resultId", job.getResultId());

				return Mono
					.fromCallable(() -> objectMapper.readValue(job.getScanConfigurationJson(), ScanConfiguration.class))
					.doOnNext((conf) -> model.addAttribute("config", conf))
					.onErrorResume((e) -> Mono.empty())
					.then(Mono.defer(() -> {
						if (job.getStatus() == JobStatus.COMPLETED && job.getResultId() != null) {
							return scanResultService.findById(job.getResultId()).doOnNext((result) -> {
								model.addAttribute("result", result);
								model.addAttribute("globalGrade", computeGrade(result.riskSummary()));
							}).then();
						}
						return Mono.empty();
					}))
					.thenReturn("fragments/scan-queued :: scanQueued");
			});
	}

	/**
	 * Resolves the plan names of all given jobs with a single query.
	 * @param jobs the list of jobs
	 * @return a mono emitting the updated list of jobs
	 */
	private Mono<List<ScanJobEntity>> populatePlanNames(List<ScanJobEntity> jobs) {
		List<Long> planIds = jobs.stream()
			.map(ScanJobEntity::getTestPlanId)
			.filter(Objects::nonNull)
			.distinct()
			.toList();
		if (planIds.isEmpty()) {
			return Mono.just(jobs);
		}
		return testPlanRepository.findAllById(planIds)
			.collectMap(TestPlanEntity::getId, TestPlanEntity::getName)
			.map((planNames) -> {
				for (ScanJobEntity job : jobs) {
					if (job.getTestPlanId() != null) {
						job.setPlanName(planNames.get(job.getTestPlanId()));
					}
				}
				return jobs;
			});
	}

	/**
	 * Computes the A-F grade of a scan from its risk summary.
	 * @param riskSummary the risk summary
	 * @return the grade string
	 */
	private static String computeGrade(Map<RiskLevel, Long> riskSummary) {
		if (riskSummary.getOrDefault(RiskLevel.CRITICAL, 0L) > 0) {
			return "F";
		}
		if (riskSummary.getOrDefault(RiskLevel.HIGH, 0L) > 0) {
			return "D";
		}
		if (riskSummary.getOrDefault(RiskLevel.MEDIUM, 0L) > 0) {
			return "C";
		}
		if (riskSummary.getOrDefault(RiskLevel.LOW, 0L) > 0) {
			return "B";
		}
		return "A";
	}

}

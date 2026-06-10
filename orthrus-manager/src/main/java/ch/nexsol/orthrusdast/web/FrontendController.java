package ch.nexsol.orthrusdast.web;

import ch.nexsol.orthrusdast.auth.OAuth2TokenFetcher;
import ch.nexsol.orthrusdast.model.OAuth2Config;
// ch.nexsol.orthrusdast.engine.ScanService removed
import ch.nexsol.orthrusdast.model.ScanConfiguration;
import ch.nexsol.orthrusdast.model.GatewayType;
import java.util.Arrays;
import java.util.stream.Collectors;
import ch.nexsol.orthrusdast.model.ScanResult;
import ch.nexsol.orthrusdast.model.SecurityScheme;
import ch.nexsol.orthrusdast.report.PdfReportGenerator;
import ch.nexsol.orthrusdast.report.HtmlReportGenerator;
import ch.nexsol.orthrusdast.repository.ScanResultRepository;
import ch.nexsol.orthrusdast.sse.JobEvent;
import ch.nexsol.orthrusdast.sse.JobEventPublisher;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.codec.ServerSentEvent;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.io.ByteArrayOutputStream;
import java.util.List;

import ch.nexsol.orthrusdast.engine.ScanResultService;
import ch.nexsol.orthrusdast.engine.StatisticsService;

import ch.nexsol.orthrusdast.entity.ScanJobEntity;
import ch.nexsol.orthrusdast.entity.SlaveNodeEntity;
import ch.nexsol.orthrusdast.entity.TestPlanEntity;
import ch.nexsol.orthrusdast.model.AttemptStatus;
import ch.nexsol.orthrusdast.model.EndpointAttemptGroup;
import ch.nexsol.orthrusdast.model.JobStatus;
import ch.nexsol.orthrusdast.model.NodeStatus;
import ch.nexsol.orthrusdast.model.RiskLevel;
import ch.nexsol.orthrusdast.model.ScanAttempt;
import ch.nexsol.orthrusdast.model.Vulnerability;
import ch.nexsol.orthrusdast.repository.ScanJobRepository;
import ch.nexsol.orthrusdast.repository.SlaveNodeRepository;
import ch.nexsol.orthrusdast.repository.TestPlanRepository;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.reactive.function.client.WebClient;

@Controller
public class FrontendController {

	private final ScanResultService scanResultService;

	private final PdfReportGenerator pdfReportGenerator;

	private final HtmlReportGenerator htmlReportGenerator;

	private final OAuth2TokenFetcher tokenFetcher;

	private final StatisticsService statisticsService;

	private final ScanJobRepository scanJobRepository;

	private final TestPlanRepository testPlanRepository;

	private final SlaveNodeRepository slaveNodeRepository;

	private final tools.jackson.databind.ObjectMapper objectMapper;

	private final WebClient webClient;

	private final JobEventPublisher jobEventPublisher;

	private final ObjectProvider<ReactiveClientRegistrationRepository> clientRegistrations;

	public FrontendController(ScanResultService scanResultService, PdfReportGenerator pdfReportGenerator,
			HtmlReportGenerator htmlReportGenerator, OAuth2TokenFetcher tokenFetcher,
			StatisticsService statisticsService, ScanJobRepository scanJobRepository,
			TestPlanRepository testPlanRepository, SlaveNodeRepository slaveNodeRepository,
			tools.jackson.databind.ObjectMapper objectMapper, JobEventPublisher jobEventPublisher,
			ObjectProvider<ReactiveClientRegistrationRepository> clientRegistrations) {
		this.scanResultService = scanResultService;
		this.pdfReportGenerator = pdfReportGenerator;
		this.htmlReportGenerator = htmlReportGenerator;
		this.tokenFetcher = tokenFetcher;
		this.statisticsService = statisticsService;
		this.scanJobRepository = scanJobRepository;
		this.testPlanRepository = testPlanRepository;
		this.slaveNodeRepository = slaveNodeRepository;
		this.objectMapper = objectMapper;
		this.webClient = WebClient.builder().build();
		this.jobEventPublisher = jobEventPublisher;
		this.clientRegistrations = clientRegistrations;
	}

	@GetMapping("/login")
	public Mono<String> login(ServerWebExchange exchange, Model model) {
		model.addAttribute("oauth2Enabled", clientRegistrations.getIfAvailable() != null);
		if (exchange.getRequest().getQueryParams().containsKey("error")) {
			model.addAttribute("loginError", true);
		}
		if (exchange.getRequest().getQueryParams().containsKey("error_oauth2")) {
			model.addAttribute("loginErrorOauth2", true);
		}
		if (exchange.getRequest().getQueryParams().containsKey("logout")) {
			model.addAttribute("logoutMessage", true);
		}
		return Mono.just("login");
	}

	@GetMapping("/manual")
	public String manual(Model model) {
		return "manual";
	}

	@GetMapping("/system")
	public Mono<String> systemStatus(Model model) {
		return Mono.zip(scanJobRepository.findAll().collectList(), slaveNodeRepository.findAll().collectList())
			.map(tuple -> {
				List<ScanJobEntity> jobs = tuple.getT1()
					.stream()
					.filter(j -> j.getStatus() == JobStatus.PENDING || j.getStatus() == JobStatus.RUNNING)
					.collect(Collectors.toList());
				jobs.sort((j1, j2) -> Long.compare(j2.getId(), j1.getId()));
				List<SlaveNodeEntity> slaves = tuple.getT2();

				Map<String, Long> activeJobsCount = new HashMap<>();
				for (SlaveNodeEntity slave : slaves) {
					long count = jobs.stream()
						.filter(j -> slave.getId().equals(j.getAssignedSlaveId()) && j.getStatus() == JobStatus.RUNNING)
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
		return scanJobRepository.findById(id).flatMap(job -> {
			try {
				ScanConfiguration oldConfig = objectMapper.readValue(job.getScanConfigurationJson(),
						ScanConfiguration.class);
				if (oldConfig.oauth2Config() != null) {
					return tokenFetcher.fetchTokens(oldConfig.oauth2Config())
						.defaultIfEmpty(List.of())
						.flatMap(fetchedTokens -> {
							SecurityScheme authScheme = oldConfig.authScheme();
							SecurityScheme secondaryAuthScheme = oldConfig.secondaryAuthScheme();
							if (!fetchedTokens.isEmpty()) {
								authScheme = fetchedTokens.get(0);
								if (fetchedTokens.size() > 1) {
									secondaryAuthScheme = fetchedTokens.get(1);
								}
							}
							ScanConfiguration updatedConfig = new ScanConfiguration(oldConfig.includeScanners(),
									oldConfig.excludeScanners(), oldConfig.concurrency(),
									oldConfig.httpConnectTimeoutMs(), oldConfig.httpReadTimeoutMs(),
									oldConfig.ignoreSslErrors(), oldConfig.reportFormat(), authScheme,
									secondaryAuthScheme, oldConfig.language(), oldConfig.includePassed(),
									oldConfig.gatewayType(), oldConfig.appUrl(), oldConfig.k8sToken(),
									oldConfig.oauth2Config(), oldConfig.openapiOverrideHost());
							try {
								String updatedConfigJson = objectMapper.writeValueAsString(updatedConfig);
								ScanJobEntity newJob = prepareReplayedJob(job, updatedConfigJson);
								return scanJobRepository.save(newJob);
							}
							catch (Exception e) {
								return Mono.error(e);
							}
						});
				}
			}
			catch (Exception e) {
				// fallback
			}

			ScanJobEntity newJob = prepareReplayedJob(job, job.getScanConfigurationJson());
			return scanJobRepository.save(newJob);
		})
			.doOnNext(newJob -> jobEventPublisher.emit(newJob.getId(),
					JobEvent.queued(newJob.getId(), newJob.getTarget())))
			.thenReturn("redirect:/scans/all");
	}

	private ScanJobEntity prepareReplayedJob(ScanJobEntity job, String updatedConfigJson) {
		if (job.getStatus() == JobStatus.COMPLETED) {
			return new ScanJobEntity(job.getDiscovererId(), job.getTarget(), updatedConfigJson, JobStatus.PENDING,
					job.getTestPlanId());
		}
		else {
			job.setScanConfigurationJson(updatedConfigJson);
			job.setStatus(JobStatus.PENDING);
			job.setAssignedSlaveId(null);
			job.setStartedAt(null);
			job.setCompletedAt(null);
			job.setResultId(null);
			job.setVulnsCount(null);
			job.setTestsCount(null);
			return job;
		}
	}

	@PostMapping("/system/slaves/{id}/toggle-active")
	public Mono<String> toggleSlaveActive(@PathVariable String id) {
		return slaveNodeRepository.findById(id)
			.flatMap(slave -> slaveNodeRepository.updateSlaveNodeIsActive(id, !slave.getIsActive()))
			.thenReturn("redirect:/system");
	}

	@PostMapping("/system/slaves/{id}/concurrency")
	public Mono<String> updateSlaveConcurrency(@PathVariable String id, ServerWebExchange exchange) {
		return exchange.getFormData().flatMap(formData -> {
			String valStr = formData.getFirst("maxConcurrentScans");
			int maxConcurrentScans = 0;
			if (valStr != null && !valStr.isBlank()) {
				maxConcurrentScans = Integer.parseInt(valStr);
			}
			return slaveNodeRepository.updateSlaveNodeMaxConcurrentScans(id, Math.max(0, maxConcurrentScans));
		}).thenReturn("redirect:/system");
	}

	@GetMapping("/stats")
	public Mono<String> stats(Model model) {
		return Mono.zip(statisticsService.getEvolutionByTargetAndEndpoint(), statisticsService.getGlobalStatistics())
			.map(tuple -> {
				model.addAttribute("endpointStats", tuple.getT1());
				model.addAttribute("globalStats", tuple.getT2());
				return "stats";
			});
	}

	@GetMapping("/")
	public Mono<String> index(Model model) {
		Map<String, String> discovererDescriptions = new HashMap<>();
		for (String discoverer : List.of("openapi", "graphql", "blackbox", "well-known", "curl")) {
			switch (discoverer) {
				case "openapi":
					discovererDescriptions.put(discoverer,
							"Parses OpenAPI v2/v3 (Swagger) specifications to automatically discover all available endpoints, methods, parameters, and authentication schemes.");
					break;
				case "graphql":
					discovererDescriptions.put(discoverer,
							"Introspects GraphQL schemas to discover available queries, mutations, and input types, enabling deep scanning of single-endpoint APIs.");
					break;
				case "well-known":
					discovererDescriptions.put(discoverer,
							"Explores standard predictable paths (e.g., /.well-known/, /swagger-ui.html, /robots.txt) to uncover hidden API endpoints, administrative interfaces, or sensitive configuration files.");
					break;
				case "curl":
					discovererDescriptions.put(discoverer,
							"Parses raw cURL commands to extract target URLs, HTTP methods, headers, and request payloads, allowing you to easily scan specific endpoints captured from your browser.");
					break;
				case "blackbox":
					discovererDescriptions.put(discoverer,
							"Performs brute-force and fuzzing techniques across a wide range of common API routes and parameter names to blindly discover undocumented endpoints.");
					break;
				default:
					discovererDescriptions.put(discoverer,
							"Generic discovery module for analyzing and mapping API endpoints.");
			}
		}
		model.addAttribute("discoverers", discovererDescriptions);

		return scanResultService.findAll().collectList().map(history -> {
			int totalScans = history.size();
			long totalVulns = history.stream().mapToLong(scan -> scan.vulnerabilities().size()).sum();

			model.addAttribute("totalScans", totalScans);
			model.addAttribute("totalVulns", totalVulns);
			return "home";
		});
	}

	@GetMapping("/scans/{id}/details")
	public Mono<String> scanDetails(@PathVariable Long id, Model model) {
		return scanJobRepository.findById(id).flatMap(job -> {
			if (job.getResultId() != null) {
				return scanResultService.findById(job.getResultId()).flatMap(result -> {
					model.addAttribute("scanId", job.getId());
					model.addAttribute("resultId", job.getResultId());
					model.addAttribute("targetUrl", result.targetUrl());
					model.addAttribute("discovererId", job.getDiscovererId());
					try {
						ScanConfiguration conf = objectMapper.readValue(job.getScanConfigurationJson(),
								ScanConfiguration.class);
						model.addAttribute("config", conf);
					}
					catch (Exception e) {
						model.addAttribute("config", result.configuration());
					}
					List<Vulnerability> sortedVulns = new ArrayList<>(result.vulnerabilities());
					sortedVulns.sort((v1, v2) -> {
						int riskCompare = Integer.compare(v2.riskLevel().ordinal(), v1.riskLevel().ordinal());
						if (riskCompare != 0)
							return riskCompare;
						String cwe1 = v1.cwe() != null ? v1.cwe().name() : "";
						String cwe2 = v2.cwe() != null ? v2.cwe().name() : "";
						int cweCompare = cwe1.compareTo(cwe2);
						if (cweCompare != 0)
							return cweCompare;
						String name1 = v1.name() != null ? v1.name() : "";
						String name2 = v2.name() != null ? v2.name() : "";
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

					String grade = "A";
					if (critical > 0)
						grade = "F";
					else if (high > 0)
						grade = "D";
					else if (medium > 0)
						grade = "C";
					else if (low > 0)
						grade = "B";
					model.addAttribute("globalGrade", grade);

					if (result.attempts() != null && !result.attempts().isEmpty()) {
						LinkedHashMap<String, List<ScanAttempt>> grouped = new LinkedHashMap<>();
						for (ScanAttempt a : result.attempts()) {
							String key = a.operationMethod() + " " + a.operationUrl();
							grouped.computeIfAbsent(key, k -> new ArrayList<>()).add(a);
						}

						List<EndpointAttemptGroup> attemptGroupsList = new ArrayList<>();
						for (Map.Entry<String, List<ScanAttempt>> entry : grouped.entrySet()) {
							long passed = entry.getValue()
								.stream()
								.filter(a -> AttemptStatus.PASSED == a.status())
								.count();
							long failed = entry.getValue()
								.stream()
								.filter(a -> AttemptStatus.FAILED == a.status())
								.count();
							long authError = entry.getValue()
								.stream()
								.filter(a -> AttemptStatus.AUTH_ERROR == a.status())
								.count();
							long error = entry.getValue()
								.stream()
								.filter(a -> AttemptStatus.ERROR == a.status())
								.count();
							attemptGroupsList.add(new EndpointAttemptGroup(entry.getKey(), entry.getValue(), passed,
									failed, authError, error));
						}
						model.addAttribute("attemptGroups", attemptGroupsList);
					}

					return Mono.just("scans/details");
				});
			}
			return Mono.just("redirect:/scans");
		}).switchIfEmpty(Mono.just("redirect:/scans"));
	}

	@GetMapping("/plans/new")
	public Mono<String> newTestPlan(Model model) {
		return Mono.zip(scanJobRepository.findAll().collectList(), slaveNodeRepository.findAll().collectList())
			.flatMap(tuple -> {
				List<ScanJobEntity> jobs = tuple.getT1();
				List<SlaveNodeEntity> slaves = tuple.getT2();

				long totalCapacity = 0;
				long activeJobsTotal = 0;
				long availableCapacity = 0;

				for (SlaveNodeEntity slave : slaves) {
					if (slave.getStatus() != NodeStatus.OFFLINE) {
						totalCapacity += slave.getMaxConcurrentScans();
						long activeJobs = jobs.stream()
							.filter(j -> slave.getId().equals(j.getAssignedSlaveId())
									&& j.getStatus() == JobStatus.RUNNING)
							.count();
						activeJobsTotal += activeJobs;
						availableCapacity += Math.max(0, slave.getMaxConcurrentScans() - activeJobs);
					}
				}
				model.addAttribute("hasOnlineSlaves", totalCapacity > 0);
				model.addAttribute("allSlavesBusy", totalCapacity > 0 && availableCapacity == 0);

				SlaveNodeEntity activeSlave = slaves.stream()
					.filter(s -> s.getStatus() != NodeStatus.OFFLINE)
					.findFirst()
					.orElse(null);

				if (activeSlave != null) {
					return webClient.get()
						.uri(activeSlave.getUrl() + "/api/v1/slave/capabilities")
						.retrieve()
						.bodyToMono(CapabilitiesResponse.class)
						.map(caps -> {
							model.addAttribute("discoverers", caps.discoverers());
							model.addAttribute("scanners", caps.scanners());
							return "plans/edit";
						})
						.onErrorResume(e -> {
							model.addAttribute("discoverers",
									List.of("openapi", "graphql", "blackbox", "well-known", "curl"));
							model.addAttribute("scanners", List.of());
							model.addAttribute("error", "Failed to fetch capabilities from active slave: "
									+ e.getMessage() + ". Using default discoverers.");
							return Mono.just("plans/edit");
						});
				}
				else {
					model.addAttribute("discoverers", List.of("openapi", "graphql", "blackbox", "well-known", "curl"));
					model.addAttribute("scanners", List.of());
					return Mono.just("plans/edit");
				}
			});
	}

	@GetMapping("/plans")
	public Mono<String> listTestPlans(Model model) {
		return Mono.zip(testPlanRepository.findAll().collectList(), slaveNodeRepository.findAll().collectList())
			.flatMap(tuple -> {
				List<TestPlanEntity> plans = tuple.getT1();
				List<SlaveNodeEntity> slaves = tuple.getT2();

				boolean hasOnlineSlaves = slaves.stream().anyMatch(slave -> slave.getStatus() != NodeStatus.OFFLINE);

				// Get capabilities if slaves are online to know total scanners
				Mono<Integer> totalScannersMono = Mono.just(0);
				if (hasOnlineSlaves) {
					SlaveNodeEntity activeSlave = slaves.stream()
						.filter(s -> s.getStatus() != NodeStatus.OFFLINE)
						.findFirst()
						.orElse(null);
					if (activeSlave != null) {
						totalScannersMono = WebClient.create()
							.get()
							.uri(activeSlave.getUrl() + "/api/v1/slave/capabilities")
							.retrieve()
							.bodyToMono(CapabilitiesResponse.class)
							.map(caps -> caps.scanners() != null ? caps.scanners().size() : 0)
							.onErrorReturn(0);
					}
				}

				return totalScannersMono.map(totalScanners -> {
					List<Map<String, Object>> mappedPlans = new ArrayList<>();
					for (TestPlanEntity plan : plans) {
						Map<String, Object> map = new HashMap<>();
						map.put("plan", plan);
						try {
							ScanConfiguration conf = objectMapper.readValue(plan.getScanConfigurationJson(),
									ScanConfiguration.class);
							if (conf.includeScanners() == null || conf.includeScanners().isEmpty()) {
								map.put("scannersCount", totalScanners > 0 ? totalScanners : "All");
							}
							else {
								map.put("scannersCount", conf.includeScanners().size());
							}
						}
						catch (Exception e) {
							map.put("scannersCount", "All");
						}
						map.put("totalScanners", totalScanners > 0 ? totalScanners : "?");
						mappedPlans.add(map);
					}

					model.addAttribute("hasOnlineSlaves", hasOnlineSlaves);
					model.addAttribute("mappedPlans", mappedPlans);
					return "plans/list";
				});
			});
	}

	@PostMapping("/plans/{id}/run")
	public Mono<String> runTestPlan(@PathVariable Long id, ServerWebExchange exchange) {
		return testPlanRepository.findById(id).flatMap(plan -> {
			ScanJobEntity job = new ScanJobEntity(plan.getDiscovererId(), plan.getTarget(),
					plan.getScanConfigurationJson(), JobStatus.PENDING, plan.getId());
			return scanJobRepository.save(job).doOnSuccess(savedJob -> {
				jobEventPublisher.emit(savedJob.getId(), JobEvent.queued(savedJob.getId(), savedJob.getTarget()));
			}).thenReturn("redirect:/scans/all");
		}).switchIfEmpty(Mono.error(new IllegalArgumentException("Test plan not found")));
	}

	@PostMapping("/scans/{id}/cancel")
	public Mono<String> cancelScan(@PathVariable Long id) {
		return scanJobRepository.findById(id).flatMap(job -> {
			if (job.getStatus() == JobStatus.PENDING) {
				job.setStatus(JobStatus.CANCELLED);
				return scanJobRepository.save(job)
					.doOnSuccess(j -> jobEventPublisher.emit(j.getId(),
							JobEvent.failed(j.getId(), j.getTarget(), "Scan cancelled by user")));
			}
			else if (job.getStatus() == JobStatus.RUNNING) {
				job.setStatus(JobStatus.CANCELLED);
				return scanJobRepository.save(job)
					.doOnSuccess(j -> jobEventPublisher.emit(j.getId(),
							JobEvent.failed(j.getId(), j.getTarget(), "Scan cancelled by user")))
					.flatMap(j -> {
						if (job.getAssignedSlaveId() != null) {
							return slaveNodeRepository.findById(job.getAssignedSlaveId())
								.flatMap(slave -> webClient.delete()
									.uri(slave.getUrl() + "/api/v1/slave/scans/" + id)
									.retrieve()
									.bodyToMono(Void.class)
									.onErrorResume(e -> Mono.empty()));
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
			.flatMap(history -> {
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

				List<Mono<Map<String, Object>>> monos = new ArrayList<>();
				for (ScanJobEntity job : history) {
					Map<String, Object> map = new HashMap<>();
					map.put("job", job);
					try {
						ScanConfiguration conf = objectMapper.readValue(job.getScanConfigurationJson(),
								ScanConfiguration.class);
						map.put("config", conf);
					}
					catch (Exception e) {
					}

					if (job.getStatus() == JobStatus.COMPLETED && job.getResultId() != null) {
						Mono<Map<String, Object>> m = scanResultService.findById(job.getResultId()).map(result -> {
							map.put("result", result);

							long critical = result.riskSummary().getOrDefault(RiskLevel.CRITICAL, 0L);
							long high = result.riskSummary().getOrDefault(RiskLevel.HIGH, 0L);
							long medium = result.riskSummary().getOrDefault(RiskLevel.MEDIUM, 0L);
							long low = result.riskSummary().getOrDefault(RiskLevel.LOW, 0L);
							String grade = "A";
							if (critical > 0)
								grade = "F";
							else if (high > 0)
								grade = "D";
							else if (medium > 0)
								grade = "C";
							else if (low > 0)
								grade = "B";
							map.put("globalGrade", grade);

							return map;
						}).defaultIfEmpty(map);
						monos.add(m);
					}
					else {
						monos.add(Mono.just(map));
					}
				}

				return Flux.concat(monos).collectList().map(mappedJobs -> {
					model.addAttribute("activeJobs", mappedJobs);
					return "scans/all";
				});
			});
	}

	private int getStatusWeight(JobStatus status) {
		if (status == JobStatus.PENDING)
			return 1;
		if (status == JobStatus.RUNNING)
			return 2;
		return 3;
	}

	public record CapabilitiesResponse(List<String> discoverers, List<ScannerInfo> scanners) {
	}

	/**
	 * SSE endpoint for browsers to subscribe to live job status updates.
	 */
	@GetMapping(value = "/api/sse/jobs/{id}/events", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
	@ResponseBody
	public Flux<ServerSentEvent<JobEvent>> jobEvents(@PathVariable Long id) {
		return jobEventPublisher.stream(id)
			.map(event -> ServerSentEvent.<JobEvent>builder().event(event.status()).data(event).build());
	}

	/**
	 * SSE endpoint for browsers to subscribe to live status updates for ALL jobs.
	 */
	@GetMapping(value = "/api/sse/jobs/events", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
	@ResponseBody
	public Flux<ServerSentEvent<JobEvent>> allJobEvents() {
		return jobEventPublisher.globalStream()
			.map(event -> ServerSentEvent.<JobEvent>builder().event(event.status()).data(event).build());
	}

	@GetMapping("/scans")
	public Mono<String> listScans(Model model) {
		return scanJobRepository.findAllByOrderByCreatedAtDesc(PageRequest.of(0, 10))
			.flatMap(this::populatePlanName)
			.collectList()
			.map(history -> {
				model.addAttribute("history", history);
				return "scans/list";
			});
	}

	@GetMapping("/api/scans")
	public Mono<String> getScansFragment(@RequestParam(defaultValue = "0") int page,
			@RequestParam(defaultValue = "10") int size, Model model) {
		return scanJobRepository.findAllByOrderByCreatedAtDesc(PageRequest.of(page, size))
			.flatMap(this::populatePlanName)
			.collectList()
			.map(history -> {
				model.addAttribute("history", history);
				return "fragments/scan-items :: items";
			});
	}

	@GetMapping("/api/scans/row/{id}")
	public Mono<String> getScanRowFragment(@PathVariable Long id, Model model) {
		return scanJobRepository.findById(id).flatMap(this::populatePlanName).map(job -> {
			model.addAttribute("history", List.of(job));
			return "fragments/scan-items :: items";
		}).defaultIfEmpty("fragments/scan-items :: items");
	}

	private Mono<ScanJobEntity> populatePlanName(ScanJobEntity job) {
		if (job.getTestPlanId() != null) {
			return testPlanRepository.findById(job.getTestPlanId()).map(plan -> {
				job.setPlanName(plan.getName());
				return job;
			}).defaultIfEmpty(job);
		}
		return Mono.just(job);
	}

	@PostMapping(value = "/web/plans")
	public Mono<String> createTestPlan(ServerWebExchange exchange, Model model) {
		return exchange.getFormData().flatMap(formData -> {
			String target = formData.getFirst("target");
			String discovererId = formData.getFirst("discovererId");
			String bearerToken = formData.getFirst("bearerToken");
			String bearerTokenSecondary = formData.getFirst("bearerTokenSecondary");
			boolean includePassed = "true".equals(formData.getFirst("includePassed"));

			String gatewayType = formData.getFirst("gatewayType");
			String appUrl = formData.getFirst("appUrl");
			String k8sToken = formData.getFirst("k8sToken");
			String openapiOverrideHost = formData.getFirst("openapiOverrideHost");

			List<String> rawIncludeScanners = formData.get("includeScanners");
			final List<String> includeScanners = (rawIncludeScanners == null) ? List.of() : rawIncludeScanners;
			final List<String> excludeScanners = List.of();

			String concurrencyStr = formData.getFirst("concurrency");
			final int concurrency = (concurrencyStr != null && !concurrencyStr.isBlank())
					? Integer.parseInt(concurrencyStr) : 10;

			if (target == null || discovererId == null) {
				return Mono.error(new IllegalArgumentException("Missing target or discovererId"));
			}

			String oauth2Url = formData.getFirst("oauth2Url");
			String oauth2Grant = formData.getFirst("oauth2Grant");
			String oauth2ClientId = formData.getFirst("oauth2ClientId");
			String oauth2ClientSecret = formData.getFirst("oauth2ClientSecret");
			String oauth2CredsStr = formData.getFirst("oauth2Creds");
			List<String> oauth2Creds = (oauth2CredsStr != null && !oauth2CredsStr.isBlank())
					? Arrays.stream(oauth2CredsStr.split(",")).map(String::trim).collect(Collectors.toList()) : null;

			OAuth2Config oauth2Config = null;
			if (oauth2Url != null && !oauth2Url.isBlank() && oauth2Grant != null && !oauth2Grant.isBlank()) {
				oauth2Config = new OAuth2Config(oauth2Url, oauth2ClientId, oauth2ClientSecret, oauth2Grant,
						oauth2Creds);
			}

			final OAuth2Config finalOauth2Config = oauth2Config;

			return Mono.justOrEmpty(finalOauth2Config)
				.flatMap(config -> tokenFetcher.fetchTokens(config))
				.defaultIfEmpty(List.of())
				.flatMap(fetchedTokens -> {
					SecurityScheme authScheme = null;
					SecurityScheme secondaryAuthScheme = null;

					if (bearerToken != null && !bearerToken.isBlank()) {
						authScheme = SecurityScheme.bearer(bearerToken.trim());
					}
					if (bearerTokenSecondary != null && !bearerTokenSecondary.isBlank()) {
						secondaryAuthScheme = SecurityScheme.bearer(bearerTokenSecondary.trim());
					}

					if (!fetchedTokens.isEmpty()) {
						authScheme = fetchedTokens.get(0);
						if (fetchedTokens.size() > 1) {
							secondaryAuthScheme = fetchedTokens.get(1);
						}
					}

					ScanConfiguration scanConfig = new ScanConfiguration(includeScanners, excludeScanners, concurrency,
							5000, 10000, false, "html", authScheme, secondaryAuthScheme, "en", includePassed,
							GatewayType.fromString(gatewayType), appUrl, k8sToken, finalOauth2Config,
							openapiOverrideHost);

					return Mono.fromCallable(() -> objectMapper.writeValueAsString(scanConfig)).flatMap(configJson -> {
						String name = formData.getFirst("name");
						String description = formData.getFirst("description");
						if (name == null || name.isBlank()) {
							name = "Unnamed Plan";
						}
						TestPlanEntity plan = new TestPlanEntity(name, description, discovererId, target, configJson);
						return testPlanRepository.save(plan);
					})
						.doOnError(e -> LoggerFactory.getLogger(FrontendController.class)
							.error("Failed to create or save test plan for target: {}", target, e));
				})
				.map(savedPlan -> {
					exchange.getResponse().getHeaders().add("HX-Redirect", "/plans");
					return "fragments/scan-queued :: empty";
				});
		}).onErrorResume(e -> {
			model.addAttribute("error", "Scan failed: " + e.getMessage());
			return Mono.just("fragments/results :: errorPanel");
		});
	}

	@GetMapping("/api/plans/{id}/details")
	public Mono<String> planDetails(@PathVariable Long id, Model model) {
		return testPlanRepository.findById(id).map((plan) -> {
			model.addAttribute("plan", plan);
			return "fragments/plan-offcanvas :: details";
		}).switchIfEmpty(Mono.error(new IllegalArgumentException("Plan not found")));
	}

	@GetMapping("/api/plans/{id}/edit")
	public Mono<String> editPlanDetails(@PathVariable Long id, Model model) {
		return testPlanRepository.findById(id).flatMap((plan) -> {
			model.addAttribute("plan", plan);
			try {
				ScanConfiguration conf = objectMapper.readValue(plan.getScanConfigurationJson(),
						ScanConfiguration.class);
				model.addAttribute("config", conf);
			}
			catch (Exception ex) {
			}

			return slaveNodeRepository.findAll()
				.filter((s) -> s.getStatus() != NodeStatus.OFFLINE)
				.next()
				.flatMap((activeSlave) -> webClient.get()
					.uri(activeSlave.getUrl() + "/api/v1/slave/capabilities")
					.retrieve()
					.bodyToMono(CapabilitiesResponse.class))
				.map((caps) -> {
					model.addAttribute("discoverers", caps.discoverers());
					model.addAttribute("scanners", caps.scanners());
					return "fragments/plan-offcanvas :: edit";
				})
				.defaultIfEmpty("fragments/plan-offcanvas :: edit")
				.doOnNext((view) -> {
					if (!model.containsAttribute("discoverers")) {
						model.addAttribute("discoverers",
								List.of("openapi", "graphql", "blackbox", "well-known", "curl"));
						model.addAttribute("scanners", List.of());
					}
				});
		}).switchIfEmpty(Mono.error(new IllegalArgumentException("Plan not found")));
	}

	@PostMapping("/api/plans/{id}")
	public Mono<String> updateTestPlan(@PathVariable Long id, ServerWebExchange exchange, Model model) {
		return testPlanRepository.findById(id).flatMap((existingPlan) -> {
			return exchange.getFormData().flatMap((formData) -> {
				String name = formData.getFirst("name");
				String description = formData.getFirst("description");
				String target = formData.getFirst("target");
				String discovererId = formData.getFirst("discovererId");

				if (name == null || name.isBlank()) {
					name = "Unnamed Plan";
				}
				existingPlan.setName(name);
				existingPlan.setDescription(description);
				if (target != null && !target.isBlank()) {
					existingPlan.setTarget(target);
				}
				if (discovererId != null && !discovererId.isBlank()) {
					existingPlan.setDiscovererId(discovererId);
				}

				String gatewayType = formData.getFirst("gatewayType");
				String appUrl = formData.getFirst("appUrl");
				String k8sToken = formData.getFirst("k8sToken");
				String openapiOverrideHost = formData.getFirst("openapiOverrideHost");
				List<String> rawIncludeScanners = formData.get("includeScanners");
				final List<String> includeScanners = (rawIncludeScanners == null) ? List.of() : rawIncludeScanners;
				String concurrencyStr = formData.getFirst("concurrency");
				final int concurrency = (concurrencyStr != null && !concurrencyStr.isBlank())
						? Integer.parseInt(concurrencyStr) : 10;

				String oauth2Url = formData.getFirst("oauth2Url");
				String oauth2Grant = formData.getFirst("oauth2Grant");
				String oauth2ClientId = formData.getFirst("oauth2ClientId");
				String oauth2ClientSecret = formData.getFirst("oauth2ClientSecret");
				String oauth2CredsStr = formData.getFirst("oauth2Creds");
				List<String> oauth2Creds = (oauth2CredsStr != null && !oauth2CredsStr.isBlank())
						? Arrays.stream(oauth2CredsStr.split(",")).map(String::trim).collect(Collectors.toList())
						: null;

				String bearerToken = formData.getFirst("bearerToken");
				String bearerTokenSecondary = formData.getFirst("bearerTokenSecondary");

				try {
					ScanConfiguration oldConfig = objectMapper.readValue(existingPlan.getScanConfigurationJson(),
							ScanConfiguration.class);

					OAuth2Config oauth2Config = oldConfig.oauth2Config();
					if (oauth2Url != null && !oauth2Url.isBlank() && oauth2Grant != null && !oauth2Grant.isBlank()) {
						String secret = (oauth2ClientSecret == null || oauth2ClientSecret.isBlank())
								? (oauth2Config != null ? oauth2Config.clientSecret() : "") : oauth2ClientSecret;
						oauth2Config = new OAuth2Config(oauth2Url, oauth2ClientId, secret, oauth2Grant, oauth2Creds);
					}
					else if (oauth2Url != null && oauth2Url.isBlank()) {
						oauth2Config = null;
					}

					SecurityScheme authScheme = oldConfig.authScheme();
					SecurityScheme secondaryAuthScheme = oldConfig.secondaryAuthScheme();

					if (bearerToken != null && !bearerToken.isBlank()) {
						authScheme = SecurityScheme.bearer(bearerToken.trim());
					}
					if (bearerTokenSecondary != null && !bearerTokenSecondary.isBlank()) {
						secondaryAuthScheme = SecurityScheme.bearer(bearerTokenSecondary.trim());
					}

					ScanConfiguration scanConfig = new ScanConfiguration(includeScanners, oldConfig.excludeScanners(),
							concurrency, oldConfig.httpConnectTimeoutMs(), oldConfig.httpReadTimeoutMs(),
							oldConfig.ignoreSslErrors(), oldConfig.reportFormat(), authScheme, secondaryAuthScheme,
							oldConfig.language(), oldConfig.includePassed(),
							(gatewayType != null) ? GatewayType.fromString(gatewayType) : oldConfig.gatewayType(),
							appUrl, k8sToken, oauth2Config, openapiOverrideHost);

					existingPlan.setScanConfigurationJson(objectMapper.writeValueAsString(scanConfig));
				}
				catch (Exception ex) {
					// Fallback
				}

				return testPlanRepository.save(existingPlan);
			});
		}).map((savedPlan) -> {
			exchange.getResponse().getHeaders().add("HX-Redirect", "/plans");
			return "fragments/scan-queued :: empty";
		}).onErrorResume((ex) -> {
			LoggerFactory.getLogger(FrontendController.class).error("Failed to update test plan: {}", id, ex);
			model.addAttribute("error", "Update failed: " + ex.getMessage());
			return Mono.just("fragments/results :: errorPanel");
		});
	}

	@GetMapping(value = "/web/scans/{id}/html", produces = MediaType.TEXT_HTML_VALUE)
	public Mono<Void> getHtmlReport(@PathVariable String id, @RequestParam(defaultValue = "true") boolean includePassed,
			ServerWebExchange exchange) {
		return scanResultService.findById(id).flatMap(result -> {
			exchange.getResponse().setStatusCode(HttpStatus.OK);
			return exchange.getResponse().writeWith(Mono.create(sink -> {
				try {
					ByteArrayOutputStream out = new ByteArrayOutputStream();
					htmlReportGenerator.generateReport(result, out, includePassed).doOnSuccess(v -> {
						DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(out.toByteArray());
						sink.success(buffer);
					}).doOnError(sink::error).subscribe();
				}
				catch (Exception e) {
					sink.error(e);
				}
			}));
		}).then();
	}

	@GetMapping("/web/scans/{id}/pdf")
	public Mono<ResponseEntity<Resource>> downloadPdf(@PathVariable String id,
			@RequestParam(defaultValue = "false") boolean includePassed) {
		return scanResultService.findById(id).flatMap(result -> scanJobRepository.findByResultId(id).map(job -> {
			try {
				ScanConfiguration config = objectMapper.readValue(job.getScanConfigurationJson(),
						ScanConfiguration.class);
				return new ScanResult(result.id(), result.targetUrl(), result.scanStartTime(), result.scanEndTime(),
						result.operationsDiscovered(), result.operationsScanned(), result.vulnerabilities(),
						result.riskSummary(), result.scannerSummary(), config, result.attempts(),
						job.getDiscovererId());
			}
			catch (Exception e) {
				return result;
			}
		}).defaultIfEmpty(result)).flatMap(result -> {
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			return pdfReportGenerator.generateReport(result, out, includePassed)
				.then(Mono.fromCallable(() -> new ByteArrayResource(out.toByteArray())));
		})
			.map(resource -> ResponseEntity.ok()
				.header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"orthrus-report.pdf\"")
				.contentType(MediaType.APPLICATION_PDF)
				.body((Resource) resource))
			.defaultIfEmpty(ResponseEntity.notFound().<Resource>build());
	}

	public record ScannerInfo(String id, String name, String type) {
		public String getId() {
			return id;
		}

		public String getName() {
			return name;
		}

		public String getType() {
			return type;
		}
	}

}

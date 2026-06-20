package ch.nexsol.orthrusdast.web;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;

import ch.nexsol.orthrusdast.auth.OAuth2TokenFetcher;
import ch.nexsol.orthrusdast.entity.ScanJobEntity;
import ch.nexsol.orthrusdast.entity.SlaveNodeEntity;
import ch.nexsol.orthrusdast.entity.TestPlanEntity;
import ch.nexsol.orthrusdast.model.GatewayType;
import ch.nexsol.orthrusdast.model.JobStatus;
import ch.nexsol.orthrusdast.model.NodeStatus;
import ch.nexsol.orthrusdast.model.OAuth2Config;
import ch.nexsol.orthrusdast.model.ScanConfiguration;
import ch.nexsol.orthrusdast.model.SecurityScheme;
import ch.nexsol.orthrusdast.repository.ScanJobRepository;
import ch.nexsol.orthrusdast.repository.ScanTaskRepository;
import ch.nexsol.orthrusdast.repository.SlaveNodeRepository;
import ch.nexsol.orthrusdast.repository.TestPlanRepository;
import ch.nexsol.orthrusdast.sse.JobEvent;
import ch.nexsol.orthrusdast.sse.JobEventPublisher;
import reactor.core.publisher.Mono;
import tools.jackson.databind.ObjectMapper;

/**
 * Test-plan pages: listing, creation, edition and execution.
 */
@Controller
public class PlanController {

	private static final Logger log = LoggerFactory.getLogger(PlanController.class);

	static final List<String> DEFAULT_DISCOVERERS = List.of("openapi", "graphql", "blackbox", "well-known", "curl");

	private final TestPlanRepository testPlanRepository;

	private final ScanJobRepository scanJobRepository;

	private final SlaveNodeRepository slaveNodeRepository;

	private final ScanTaskRepository scanTaskRepository;

	private final OAuth2TokenFetcher tokenFetcher;

	private final ObjectMapper objectMapper;

	private final JobEventPublisher jobEventPublisher;

	private final WebClient webClient;

	public PlanController(TestPlanRepository testPlanRepository, ScanJobRepository scanJobRepository,
			SlaveNodeRepository slaveNodeRepository, ScanTaskRepository scanTaskRepository,
			OAuth2TokenFetcher tokenFetcher, ObjectMapper objectMapper, JobEventPublisher jobEventPublisher,
			WebClient.Builder webClientBuilder) {
		this.testPlanRepository = testPlanRepository;
		this.scanJobRepository = scanJobRepository;
		this.slaveNodeRepository = slaveNodeRepository;
		this.scanTaskRepository = scanTaskRepository;
		this.tokenFetcher = tokenFetcher;
		this.objectMapper = objectMapper;
		this.jobEventPublisher = jobEventPublisher;
		this.webClient = webClientBuilder.build();
	}

	@GetMapping("/plans/new")
	public Mono<String> newTestPlan(Model model) {
		return Mono
			.zip(slaveNodeRepository.findAll().collectList(),
					scanTaskRepository.findByStatus(JobStatus.RUNNING).collectList())
			.flatMap(tuple -> {
				List<SlaveNodeEntity> slaves = tuple.getT1();
				List<ch.nexsol.orthrusdast.entity.ScanTaskEntity> runningTasks = tuple.getT2();

				long totalCapacity = 0;
				long availableCapacity = 0;

				for (SlaveNodeEntity slave : slaves) {
					if (slave.getStatus() != NodeStatus.OFFLINE) {
						totalCapacity += slave.getMaxConcurrentScans();
						long activeJobs = runningTasks.stream()
							.filter(t -> slave.getId().equals(t.getAssignedSlaveId()))
							.count();
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
					return fetchCapabilities(activeSlave).map(caps -> {
						model.addAttribute("discoverers", caps.discoverers());
						model.addAttribute("scanners", caps.scanners());
						return "plans/edit";
					}).onErrorResume(e -> {
						log.warn("Failed to fetch capabilities from slave {}", activeSlave.getId(), e);
						model.addAttribute("discoverers", DEFAULT_DISCOVERERS);
						model.addAttribute("scanners", List.of());
						model.addAttribute("error", "Failed to fetch capabilities from active slave: " + e.getMessage()
								+ ". Using default discoverers.");
						return Mono.just("plans/edit");
					});
				}
				else {
					model.addAttribute("discoverers", DEFAULT_DISCOVERERS);
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
						totalScannersMono = fetchCapabilities(activeSlave)
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
							log.warn("Failed to parse configuration of plan {}", plan.getId(), e);
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

			final int concurrency = WebFormUtils.parseIntOrDefault(formData.getFirst("concurrency"), 10);

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
					}).doOnError(e -> log.error("Failed to create or save test plan for target: {}", target, e));
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
				log.warn("Failed to parse configuration of plan {}", plan.getId(), ex);
			}

			return slaveNodeRepository.findAll()
				.filter((s) -> s.getStatus() != NodeStatus.OFFLINE)
				.next()
				.flatMap(this::fetchCapabilities)
				.onErrorResume((e) -> {
					log.warn("Failed to fetch capabilities from active slave", e);
					return Mono.empty();
				})
				.map((caps) -> {
					model.addAttribute("discoverers", caps.discoverers());
					model.addAttribute("scanners", caps.scanners());
					return "fragments/plan-offcanvas :: edit";
				})
				.defaultIfEmpty("fragments/plan-offcanvas :: edit")
				.doOnNext((view) -> {
					if (!model.containsAttribute("discoverers")) {
						model.addAttribute("discoverers", DEFAULT_DISCOVERERS);
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
				final int concurrency = WebFormUtils.parseIntOrDefault(formData.getFirst("concurrency"), 10);

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
					// Saving without the new configuration would silently discard the
					// user's changes — fail loudly instead.
					return Mono.error(new IllegalStateException(
							"Failed to update the scan configuration of plan " + id, ex));
				}

				return testPlanRepository.save(existingPlan);
			});
		}).map((savedPlan) -> {
			exchange.getResponse().getHeaders().add("HX-Redirect", "/plans");
			return "fragments/scan-queued :: empty";
		}).onErrorResume((ex) -> {
			log.error("Failed to update test plan: {}", id, ex);
			model.addAttribute("error", "Update failed: " + ex.getMessage());
			return Mono.just("fragments/results :: errorPanel");
		});
	}

	private Mono<CapabilitiesResponse> fetchCapabilities(SlaveNodeEntity slave) {
		return webClient.get()
			.uri(slave.getUrl() + "/api/v1/slave/capabilities")
			.retrieve()
			.bodyToMono(CapabilitiesResponse.class);
	}

	public record CapabilitiesResponse(List<String> discoverers, List<ScannerInfo> scanners) {
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

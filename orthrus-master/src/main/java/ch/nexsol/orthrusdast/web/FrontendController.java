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

@Controller
public class FrontendController {

    private final ScanResultService scanResultService;
    private final PdfReportGenerator pdfReportGenerator;
    private final OAuth2TokenFetcher tokenFetcher;
    private final StatisticsService statisticsService;
    private final ch.nexsol.orthrusdast.repository.ScanJobRepository scanJobRepository;
    private final ch.nexsol.orthrusdast.repository.SlaveNodeRepository slaveNodeRepository;
    private final tools.jackson.databind.ObjectMapper objectMapper;
    private final org.springframework.web.reactive.function.client.WebClient webClient;
    private final JobEventPublisher jobEventPublisher;

    public FrontendController(ScanResultService scanResultService, PdfReportGenerator pdfReportGenerator,
            OAuth2TokenFetcher tokenFetcher, StatisticsService statisticsService,
            ch.nexsol.orthrusdast.repository.ScanJobRepository scanJobRepository,
            ch.nexsol.orthrusdast.repository.SlaveNodeRepository slaveNodeRepository,
            tools.jackson.databind.ObjectMapper objectMapper,
            JobEventPublisher jobEventPublisher) {
        this.scanResultService = scanResultService;
        this.pdfReportGenerator = pdfReportGenerator;
        this.tokenFetcher = tokenFetcher;
        this.statisticsService = statisticsService;
        this.scanJobRepository = scanJobRepository;
        this.slaveNodeRepository = slaveNodeRepository;
        this.objectMapper = objectMapper;
        this.webClient = org.springframework.web.reactive.function.client.WebClient.builder().build();
        this.jobEventPublisher = jobEventPublisher;
    }

    @GetMapping("/manual")
    public String manual(Model model) {
        return "manual";
    }

    @GetMapping("/system")
    public Mono<String> systemStatus(Model model) {
        return Mono.zip(
                scanJobRepository.findAll().collectList(),
                slaveNodeRepository.findAll().collectList()).map(tuple -> {
                    java.util.List<ch.nexsol.orthrusdast.entity.ScanJobEntity> jobs = tuple.getT1().stream()
                            .filter(j -> j.getStatus() == ch.nexsol.orthrusdast.model.JobStatus.PENDING || j.getStatus() == ch.nexsol.orthrusdast.model.JobStatus.RUNNING)
                            .collect(java.util.stream.Collectors.toList());
                    jobs.sort((j1, j2) -> Long.compare(j2.getId(), j1.getId()));
                    java.util.List<ch.nexsol.orthrusdast.entity.SlaveNodeEntity> slaves = tuple.getT2();

                    java.util.Map<String, Long> activeJobsCount = new java.util.HashMap<>();
                    for (ch.nexsol.orthrusdast.entity.SlaveNodeEntity slave : slaves) {
                        long count = jobs.stream()
                                .filter(j -> slave.getId().equals(j.getAssignedSlaveId())
                                        && j.getStatus() == ch.nexsol.orthrusdast.model.JobStatus.RUNNING)
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
    public Mono<String> restartJob(@org.springframework.web.bind.annotation.PathVariable Long id) {
        return scanJobRepository.findById(id)
                .flatMap(job -> {
                    ch.nexsol.orthrusdast.entity.ScanJobEntity newJob = new ch.nexsol.orthrusdast.entity.ScanJobEntity(
                            job.getDiscovererId(),
                            job.getTarget(),
                            job.getScanConfigurationJson(),
                            ch.nexsol.orthrusdast.model.JobStatus.PENDING
                    );
                    return scanJobRepository.save(newJob);
                })
                .thenReturn("redirect:/scans/all");
    }

    @PostMapping("/system/slaves/{id}/toggle-active")
    public Mono<String> toggleSlaveActive(@org.springframework.web.bind.annotation.PathVariable String id) {
        return slaveNodeRepository.findById(id)
                .flatMap(slave -> slaveNodeRepository.updateSlaveNodeIsActive(id, !slave.getIsActive()))
                .thenReturn("redirect:/system");
    }

    @PostMapping("/system/slaves/{id}/concurrency")
    public Mono<String> updateSlaveConcurrency(@org.springframework.web.bind.annotation.PathVariable String id,
            ServerWebExchange exchange) {
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
        return Mono.zip(
                statisticsService.getEvolutionByTargetAndEndpoint(),
                statisticsService.getGlobalStatistics()).map(tuple -> {
                    model.addAttribute("endpointStats", tuple.getT1());
                    model.addAttribute("globalStats", tuple.getT2());
                    return "stats";
                });
    }

    @GetMapping("/")
    public Mono<String> index(Model model) {
        java.util.Map<String, String> discovererDescriptions = new java.util.HashMap<>();
        for (String discoverer : java.util.List.of("openapi", "graphql", "blackbox", "well-known", "curl")) {
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
            long totalVulns = history.stream()
                    .mapToLong(scan -> scan.vulnerabilities().size())
                    .sum();

            model.addAttribute("totalScans", totalScans);
            model.addAttribute("totalVulns", totalVulns);
            return "home";
        });
    }

    @GetMapping("/scans/new")
    public Mono<String> newScan(Model model) {
        return Mono.zip(
                scanJobRepository.findAll().collectList(),
                slaveNodeRepository.findAll().collectList()
        ).flatMap(tuple -> {
            java.util.List<ch.nexsol.orthrusdast.entity.ScanJobEntity> jobs = tuple.getT1();
            java.util.List<ch.nexsol.orthrusdast.entity.SlaveNodeEntity> slaves = tuple.getT2();

            long totalCapacity = 0;
            long activeJobsTotal = 0;
            long availableCapacity = 0;

            for (ch.nexsol.orthrusdast.entity.SlaveNodeEntity slave : slaves) {
                if (slave.getStatus() != ch.nexsol.orthrusdast.model.NodeStatus.OFFLINE) {
                    totalCapacity += slave.getMaxConcurrentScans();
                    long activeJobs = jobs.stream()
                            .filter(j -> slave.getId().equals(j.getAssignedSlaveId()) && j.getStatus() == ch.nexsol.orthrusdast.model.JobStatus.RUNNING)
                            .count();
                    activeJobsTotal += activeJobs;
                    availableCapacity += Math.max(0, slave.getMaxConcurrentScans() - activeJobs);
                }
            }
            model.addAttribute("hasOnlineSlaves", totalCapacity > 0);
            model.addAttribute("allSlavesBusy", totalCapacity > 0 && availableCapacity == 0);

            ch.nexsol.orthrusdast.entity.SlaveNodeEntity activeSlave = slaves.stream()
                    .filter(s -> s.getStatus() != ch.nexsol.orthrusdast.model.NodeStatus.OFFLINE)
                    .findFirst().orElse(null);

            if (activeSlave != null) {
                return webClient.get().uri(activeSlave.getUrl() + "/api/v1/slave/capabilities")
                        .retrieve()
                        .bodyToMono(CapabilitiesResponse.class)
                        .map(caps -> {
                            model.addAttribute("discoverers", caps.discoverers());
                            model.addAttribute("scanners", caps.scanners());
                            return "scans/new";
                        })
                        .onErrorResume(e -> {
                            model.addAttribute("discoverers", java.util.List.of());
                            model.addAttribute("scanners", java.util.List.of());
                            model.addAttribute("error",
                                    "Failed to fetch capabilities from active slave: " + e.getMessage());
                            return Mono.just("scans/new");
                        });
            } else {
                model.addAttribute("discoverers", java.util.List.of());
                model.addAttribute("scanners", java.util.List.of());
                return Mono.just("scans/new");
            }
        });
    }

    @PostMapping("/scans/{id}/cancel")
    public Mono<String> cancelScan(@PathVariable Long id) {
        return scanJobRepository.findById(id)
                .flatMap(job -> {
                    if (job.getStatus() == ch.nexsol.orthrusdast.model.JobStatus.PENDING) {
                        job.setStatus(ch.nexsol.orthrusdast.model.JobStatus.CANCELLED);
                        return scanJobRepository.save(job)
                                .doOnSuccess(j -> jobEventPublisher.emit(j.getId(), ch.nexsol.orthrusdast.sse.JobEvent.failed(j.getId(), j.getTarget(), "Scan cancelled by user")));
                    } else if (job.getStatus() == ch.nexsol.orthrusdast.model.JobStatus.RUNNING) {
                        job.setStatus(ch.nexsol.orthrusdast.model.JobStatus.CANCELLED);
                        return scanJobRepository.save(job)
                                .doOnSuccess(j -> jobEventPublisher.emit(j.getId(), ch.nexsol.orthrusdast.sse.JobEvent.failed(j.getId(), j.getTarget(), "Scan cancelled by user")))
                                .flatMap(j -> {
                                    if (job.getAssignedSlaveId() != null) {
                                        return slaveNodeRepository.findById(job.getAssignedSlaveId())
                                                .flatMap(slave -> webClient.delete()
                                                        .uri(slave.getUrl() + "/api/v1/slave/scans/" + id)
                                                        .retrieve()
                                                        .bodyToMono(Void.class)
                                                        .onErrorResume(e -> Mono.empty())
                                                );
                                    }
                                    return Mono.empty();
                                });
                    }
                    return Mono.empty();
                })
                .thenReturn("redirect:/scans/all");
    }

    @GetMapping("/scans/all")
    public Mono<String> activeScans(Model model) {
        return scanJobRepository.findAllByOrderByCreatedAtDesc(org.springframework.data.domain.PageRequest.of(0, 100))
                .collectList()
                .flatMap(history -> {
                    // Sort: PENDING first, then RUNNING, then everything else (COMPLETED, FAILED),
                    // and within those groups by date desc
                    history.sort((a, b) -> {
                        int aWeight = getStatusWeight(a.getStatus());
                        int bWeight = getStatusWeight(b.getStatus());
                        if (aWeight != bWeight) {
                            return Integer.compare(aWeight, bWeight);
                        }
                        return b.getCreatedAt().compareTo(a.getCreatedAt()); // desc
                    });

                    java.util.List<Mono<java.util.Map<String, Object>>> monos = new java.util.ArrayList<>();
                    for (ch.nexsol.orthrusdast.entity.ScanJobEntity job : history) {
                        java.util.Map<String, Object> map = new java.util.HashMap<>();
                        map.put("job", job);

                        if (job.getStatus() == ch.nexsol.orthrusdast.model.JobStatus.COMPLETED
                                && job.getResultId() != null) {
                            Mono<java.util.Map<String, Object>> m = scanResultService.findById(job.getResultId())
                                    .map(result -> {
                                        map.put("result", result);

                                        long critical = result.riskSummary()
                                                .getOrDefault(ch.nexsol.orthrusdast.model.RiskLevel.CRITICAL, 0L);
                                        long high = result.riskSummary()
                                                .getOrDefault(ch.nexsol.orthrusdast.model.RiskLevel.HIGH, 0L);
                                        long medium = result.riskSummary()
                                                .getOrDefault(ch.nexsol.orthrusdast.model.RiskLevel.MEDIUM, 0L);
                                        long low = result.riskSummary()
                                                .getOrDefault(ch.nexsol.orthrusdast.model.RiskLevel.LOW, 0L);
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
                                    })
                                    .defaultIfEmpty(map);
                            monos.add(m);
                        } else {
                            monos.add(Mono.just(map));
                        }
                    }

                    return Flux.concat(monos).collectList().map(mappedJobs -> {
                        model.addAttribute("activeJobs", mappedJobs);
                        return "scans/all";
                    });
                });
    }

    private int getStatusWeight(ch.nexsol.orthrusdast.model.JobStatus status) {
        if (status == ch.nexsol.orthrusdast.model.JobStatus.PENDING)
            return 1;
        if (status == ch.nexsol.orthrusdast.model.JobStatus.RUNNING)
            return 2;
        return 3;
    }

    public record CapabilitiesResponse(List<String> discoverers, List<ScannerInfo> scanners) {
    }

    /**
     * SSE endpoint for browsers to subscribe to live job status updates.
     */
    @GetMapping(value = "/api/sse/jobs/{id}/events", produces = org.springframework.http.MediaType.TEXT_EVENT_STREAM_VALUE)
    @org.springframework.web.bind.annotation.ResponseBody
    public Flux<ServerSentEvent<JobEvent>> jobEvents(@PathVariable Long id) {
        return jobEventPublisher.stream(id)
                .map(event -> ServerSentEvent.<JobEvent>builder()
                        .event(event.status())
                        .data(event)
                        .build());
    }

    /**
     * SSE endpoint for browsers to subscribe to live status updates for ALL jobs.
     */
    @GetMapping(value = "/api/sse/jobs/events", produces = org.springframework.http.MediaType.TEXT_EVENT_STREAM_VALUE)
    @org.springframework.web.bind.annotation.ResponseBody
    public Flux<ServerSentEvent<JobEvent>> allJobEvents() {
        return jobEventPublisher.globalStream()
                .map(event -> ServerSentEvent.<JobEvent>builder()
                        .event(event.status())
                        .data(event)
                        .build());
    }

    @GetMapping("/scans")
    public Mono<String> listScans(Model model) {
        return scanJobRepository.findAllByOrderByCreatedAtDesc(org.springframework.data.domain.PageRequest.of(0, 10))
                .collectList().map(history -> {
                    model.addAttribute("history", history);
                    return "scans/list";
                });
    }

    @GetMapping("/api/scans")
    public Mono<String> getScansFragment(
            @org.springframework.web.bind.annotation.RequestParam(defaultValue = "0") int page,
            @org.springframework.web.bind.annotation.RequestParam(defaultValue = "10") int size,
            Model model) {
        return scanJobRepository
                .findAllByOrderByCreatedAtDesc(org.springframework.data.domain.PageRequest.of(page, size)).collectList()
                .map(history -> {
                    model.addAttribute("history", history);
                    return "fragments/scan-items :: items";
                });
    }

    @GetMapping("/api/scans/row/{id}")
    public Mono<String> getScanRowFragment(@org.springframework.web.bind.annotation.PathVariable Long id, Model model) {
        return scanJobRepository.findById(id)
                .map(job -> {
                    model.addAttribute("history", java.util.List.of(job));
                    return "fragments/scan-items :: items";
                })
                .defaultIfEmpty("fragments/scan-items :: items");
    }

    @PostMapping(value = "/web/scans")
    public Mono<String> triggerScan(ServerWebExchange exchange, Model model) {
        return exchange.getFormData().flatMap(formData -> {
            String target = formData.getFirst("target");
            String discovererId = formData.getFirst("discovererId");
            String bearerToken = formData.getFirst("bearerToken");
            String bearerTokenSecondary = formData.getFirst("bearerTokenSecondary");
            boolean includePassed = "true".equals(formData.getFirst("includePassed"));

            String gatewayType = formData.getFirst("gatewayType");
            String appUrl = formData.getFirst("appUrl");
            String k8sToken = formData.getFirst("k8sToken");

            List<String> rawIncludeScanners = formData.get("includeScanners");
            final List<String> includeScanners = (rawIncludeScanners == null) ? List.of() : rawIncludeScanners;
            final List<String> excludeScanners = List.of();

            String concurrencyStr = formData.getFirst("concurrency");
            final int concurrency = (concurrencyStr != null && !concurrencyStr.isBlank())
                    ? Integer.parseInt(concurrencyStr)
                    : 10;

            if (target == null || discovererId == null) {
                return Mono.error(new IllegalArgumentException("Missing target or discovererId"));
            }

            String oauth2Url = formData.getFirst("oauth2Url");
            String oauth2Grant = formData.getFirst("oauth2Grant");
            String oauth2ClientId = formData.getFirst("oauth2ClientId");
            String oauth2ClientSecret = formData.getFirst("oauth2ClientSecret");
            String oauth2CredsStr = formData.getFirst("oauth2Creds");
            List<String> oauth2Creds = (oauth2CredsStr != null && !oauth2CredsStr.isBlank())
                    ? Arrays.stream(oauth2CredsStr.split(",")).map(String::trim).collect(Collectors.toList())
                    : null;

            OAuth2Config oauth2Config = null;
            if (oauth2Url != null && !oauth2Url.isBlank() && oauth2Grant != null && !oauth2Grant.isBlank()) {
                oauth2Config = new OAuth2Config(oauth2Url, oauth2ClientId, oauth2ClientSecret, oauth2Grant,
                        oauth2Creds);
            }

            return Mono.justOrEmpty(oauth2Config)
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

                        ScanConfiguration config = new ScanConfiguration(
                                includeScanners, excludeScanners, concurrency, 5000, 10000, false, "html", authScheme,
                                secondaryAuthScheme, "en", includePassed, GatewayType.fromString(gatewayType), appUrl,
                                k8sToken);

                        return Mono.fromCallable(() -> objectMapper.writeValueAsString(config))
                                .flatMap(configJson -> {
                                    ch.nexsol.orthrusdast.entity.ScanJobEntity job = new ch.nexsol.orthrusdast.entity.ScanJobEntity(
                                            discovererId, target, configJson, ch.nexsol.orthrusdast.model.JobStatus.PENDING);
                                    return scanJobRepository.save(job);
                                })
                                .doOnSuccess(savedJob -> {
                                    jobEventPublisher.emit(savedJob.getId(),
                                            JobEvent.queued(savedJob.getId(), target));
                                })
                                .doOnError(e -> org.slf4j.LoggerFactory.getLogger(FrontendController.class)
                                        .error("Failed to create or save scan job for target: {}", target, e));
                    })
                    .map(savedJob -> {
                        exchange.getResponse().getHeaders().add("HX-Redirect", "/scans/all");
                        return "fragments/scan-queued :: empty";
                    });
        }).onErrorResume(e -> {
            model.addAttribute("error", "Scan failed: " + e.getMessage());
            return Mono.just("fragments/results :: errorPanel");
        });
    }

    @GetMapping("/web/scans/{id}/pdf")
    public Mono<ResponseEntity<org.springframework.core.io.Resource>> downloadPdf(@PathVariable String id) {
        return scanResultService.findById(id)
                .flatMap(result -> {
                    ByteArrayOutputStream out = new ByteArrayOutputStream();
                    return pdfReportGenerator.generateReport(result, out)
                            .then(Mono.fromCallable(
                                    () -> new org.springframework.core.io.ByteArrayResource(out.toByteArray())));
                })
                .map(resource -> ResponseEntity.ok()
                        .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"orthrus-report.pdf\"")
                        .contentType(MediaType.APPLICATION_PDF)
                        .body((org.springframework.core.io.Resource) resource))
                .defaultIfEmpty(ResponseEntity.notFound().<org.springframework.core.io.Resource>build());
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

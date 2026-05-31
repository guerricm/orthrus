package ch.hug.orthrusdast.web;

import ch.hug.orthrusdast.auth.OAuth2TokenFetcher;
import ch.hug.orthrusdast.model.OAuth2Config;
import ch.hug.orthrusdast.engine.ScanService;
import ch.hug.orthrusdast.model.ScanConfiguration;
import java.util.Arrays;
import java.util.stream.Collectors;
import ch.hug.orthrusdast.model.ScanResult;
import ch.hug.orthrusdast.model.SecurityScheme;
import ch.hug.orthrusdast.report.PdfReportGenerator;
import ch.hug.orthrusdast.repository.ScanResultRepository;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
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

import ch.hug.orthrusdast.engine.ScanResultService;
import ch.hug.orthrusdast.engine.StatisticsService;

@Controller
public class FrontendController {

    private final ScanService scanService;
    private final ScanResultService scanResultService;
    private final PdfReportGenerator pdfReportGenerator;
    private final OAuth2TokenFetcher tokenFetcher;

    private final StatisticsService statisticsService;

    public FrontendController(ScanService scanService, ScanResultService scanResultService, PdfReportGenerator pdfReportGenerator, OAuth2TokenFetcher tokenFetcher, StatisticsService statisticsService) {
        this.scanService = scanService;
        this.scanResultService = scanResultService;
        this.pdfReportGenerator = pdfReportGenerator;
        this.tokenFetcher = tokenFetcher;
        this.statisticsService = statisticsService;
    }

    @GetMapping("/manual")
    public String manual(Model model) {
        return "manual";
    }

    @GetMapping("/stats")
    public Mono<String> stats(Model model) {
        return Mono.zip(
                statisticsService.getEvolutionByTargetAndEndpoint(),
                statisticsService.getGlobalStatistics()
        ).map(tuple -> {
            model.addAttribute("endpointStats", tuple.getT1());
            model.addAttribute("globalStats", tuple.getT2());
            return "stats";
        });
    }

    @GetMapping("/")
    public Mono<String> index(Model model) {
        java.util.Map<String, String> discovererDescriptions = new java.util.HashMap<>();
        for (String discoverer : scanService.getAvailableDiscoverers()) {
            switch (discoverer) {
                case "openapi":
                    discovererDescriptions.put(discoverer, "Parses OpenAPI v2/v3 (Swagger) specifications to automatically discover all available endpoints, methods, parameters, and authentication schemes.");
                    break;
                case "graphql":
                    discovererDescriptions.put(discoverer, "Introspects GraphQL schemas to discover available queries, mutations, and input types, enabling deep scanning of single-endpoint APIs.");
                    break;
                case "well-known":
                    discovererDescriptions.put(discoverer, "Explores standard predictable paths (e.g., /.well-known/, /swagger-ui.html, /robots.txt) to uncover hidden API endpoints, administrative interfaces, or sensitive configuration files.");
                    break;
                case "curl":
                    discovererDescriptions.put(discoverer, "Parses raw cURL commands to extract target URLs, HTTP methods, headers, and request payloads, allowing you to easily scan specific endpoints captured from your browser.");
                    break;
                case "blackbox":
                    discovererDescriptions.put(discoverer, "Performs brute-force and fuzzing techniques across a wide range of common API routes and parameter names to blindly discover undocumented endpoints.");
                    break;
                default:
                    discovererDescriptions.put(discoverer, "Generic discovery module for analyzing and mapping API endpoints.");
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
    public String newScan(Model model) {
        model.addAttribute("discoverers", scanService.getAvailableDiscoverers());
        model.addAttribute("scanners", scanService.getAvailableScannerObjects());
        return "scans/new";
    }

    @GetMapping("/scans")
    public Mono<String> listScans(Model model) {
        return scanResultService.getHistory(0, 10).collectList().map(history -> {
            model.addAttribute("history", history);
            return "scans/list";
        });
    }

    @GetMapping("/api/scans")
    public Mono<String> getScansFragment(
            @org.springframework.web.bind.annotation.RequestParam(defaultValue = "0") int page,
            @org.springframework.web.bind.annotation.RequestParam(defaultValue = "10") int size,
            Model model) {
        return scanResultService.getHistory(page, size).collectList().map(history -> {
            model.addAttribute("history", history);
            return "fragments/scan-items :: items";
        });
    }

    @PostMapping(value = "/web/scans")
    public Mono<String> triggerScan(ServerWebExchange exchange, Model model) {
        return exchange.getFormData().flatMap(formData -> {
            String target = formData.getFirst("target");
            String discovererId = formData.getFirst("discovererId");
            String bearerToken = formData.getFirst("bearerToken");
            String bearerTokenSecondary = formData.getFirst("bearerTokenSecondary");
            boolean includePassed = "true".equals(formData.getFirst("includePassed"));

            List<String> rawIncludeScanners = formData.get("includeScanners");
            final List<String> includeScanners = (rawIncludeScanners == null) ? List.of() : rawIncludeScanners;
            final List<String> excludeScanners = List.of();
            
            String concurrencyStr = formData.getFirst("concurrency");
            final int concurrency = (concurrencyStr != null && !concurrencyStr.isBlank()) ? Integer.parseInt(concurrencyStr) : 10;

            if (target == null || discovererId == null) {
                return Mono.error(new IllegalArgumentException("Missing target or discovererId"));
            }

            String oauth2Url = formData.getFirst("oauth2Url");
            String oauth2Grant = formData.getFirst("oauth2Grant");
            String oauth2ClientId = formData.getFirst("oauth2ClientId");
            String oauth2ClientSecret = formData.getFirst("oauth2ClientSecret");
            String oauth2CredsStr = formData.getFirst("oauth2Creds");
            List<String> oauth2Creds = (oauth2CredsStr != null && !oauth2CredsStr.isBlank()) ? 
                    Arrays.stream(oauth2CredsStr.split(",")).map(String::trim).collect(Collectors.toList()) : null;

            OAuth2Config oauth2Config = null;
            if (oauth2Url != null && !oauth2Url.isBlank() && oauth2Grant != null && !oauth2Grant.isBlank()) {
                oauth2Config = new OAuth2Config(oauth2Url, oauth2ClientId, oauth2ClientSecret, oauth2Grant, oauth2Creds);
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
                                includeScanners, excludeScanners, concurrency, 5000, 10000, false, "html", authScheme, secondaryAuthScheme, "en", includePassed
                        );

                        return scanService.executeScan(discovererId, target, null, config);
                    })
                    .flatMap(result -> scanResultService.save(result))
                    .map(result -> {
                        model.addAttribute("result", result);
                        // Calculate Grade for Thymeleaf
                        long critical = result.riskSummary().getOrDefault(ch.hug.orthrusdast.model.RiskLevel.CRITICAL, 0L);
                        long high = result.riskSummary().getOrDefault(ch.hug.orthrusdast.model.RiskLevel.HIGH, 0L);
                        long medium = result.riskSummary().getOrDefault(ch.hug.orthrusdast.model.RiskLevel.MEDIUM, 0L);
                        long low = result.riskSummary().getOrDefault(ch.hug.orthrusdast.model.RiskLevel.LOW, 0L);
                        String grade = "A";
                        if (critical > 0) grade = "F";
                        else if (high > 0) grade = "D";
                        else if (medium > 0) grade = "C";
                        else if (low > 0) grade = "B";
                        model.addAttribute("globalGrade", grade);
                        return "fragments/results :: resultsPanel";
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
                            .then(Mono.fromCallable(() -> new org.springframework.core.io.ByteArrayResource(out.toByteArray())));
                })
                .map(resource -> ResponseEntity.ok()
                        .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"orthrus-report.pdf\"")
                        .contentType(MediaType.APPLICATION_PDF)
                        .body((org.springframework.core.io.Resource) resource))
                .defaultIfEmpty(ResponseEntity.notFound().build());
    }
}

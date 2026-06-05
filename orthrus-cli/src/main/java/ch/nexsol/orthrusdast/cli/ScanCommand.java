package ch.nexsol.orthrusdast.cli;

import ch.nexsol.orthrusdast.engine.ScanService;
import ch.nexsol.orthrusdast.model.ScanConfiguration;
import ch.nexsol.orthrusdast.model.ScanResult;
import ch.nexsol.orthrusdast.model.SecurityScheme;
import ch.nexsol.orthrusdast.model.GatewayType;
import ch.nexsol.orthrusdast.report.ReportGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.FileOutputStream;
import java.io.OutputStream;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.function.Function;
import java.util.stream.Collectors;

import ch.nexsol.orthrusdast.auth.OAuth2TokenFetcher;
import ch.nexsol.orthrusdast.model.OAuth2Config;

@Component
@Command(name = "scan", description = "Run a VulnAPI security scan", mixinStandardHelpOptions = true)
public class ScanCommand implements Callable<Integer> {

    private static final Logger log = LoggerFactory.getLogger(ScanCommand.class);

    private final ScanService scanService;
    private final Map<String, ReportGenerator> reportGenerators;
    private final OAuth2TokenFetcher tokenFetcher;

    public ScanCommand(ScanService scanService, List<ReportGenerator> generators, OAuth2TokenFetcher tokenFetcher) {
        this.scanService = scanService;
        this.reportGenerators = generators.stream()
                .collect(Collectors.toMap(ReportGenerator::getFormat, Function.identity()));
        this.tokenFetcher = tokenFetcher;
    }

    @Option(names = {"-d", "--discoverer"}, description = "Discoverer to use (openapi, blackbox, curl, well-known, gateway)", required = true)
    String discovererId;

    @Option(names = {"-t", "--target"}, description = "Target URL or Spec path", required = true)
    String target;

    @Option(names = {"--host"}, description = "Override host URL")
    String overrideHost;

    @Option(names = {"-f", "--format"}, description = "Report format (json, sarif, html, pdf, console)", defaultValue = "console")
    String format;

    @Option(names = {"--lang"}, description = "Report language (en, fr)", defaultValue = "en")
    String language;

    @Option(names = {"-o", "--out"}, description = "Output file path (default: stdout)")
    String outputFile;

    @Option(names = {"--auth-bearer"}, description = "Bearer token for API authentication (User A)")
    String bearerToken;

    @Option(names = {"--auth-bearer-secondary"}, description = "Secondary Bearer token for Cross-User BOLA testing (User B)")
    String secondaryBearerToken;

    @Option(names = {"--include"}, description = "Comma-separated list of scanners to include", split = ",")
    List<String> includeScanners;

    @Option(names = {"--exclude"}, description = "Comma-separated list of scanners to exclude", split = ",")
    List<String> excludeScanners;

    @Option(names = {"--oauth2-url"}, description = "OAuth2 token endpoint URL")
    String oauth2Url;

    @Option(names = {"--include-passed"}, description = "Include passed tests in the report")
    boolean includePassed;

    @Option(names = {"--oauth2-client-id"}, description = "OAuth2 Client ID")
    String oauth2ClientId;

    @Option(names = {"--oauth2-client-secret"}, description = "OAuth2 Client Secret")
    String oauth2ClientSecret;

    @Option(names = {"--oauth2-grant"}, description = "OAuth2 Grant Type (password, client_credentials)")
    String oauth2Grant;

    @Option(names = {"--oauth2-creds"}, description = "Comma-separated list of user:pass credentials", split = ",")
    List<String> oauth2Creds;

    @Option(names = {"-c", "--concurrency"}, description = "Number of concurrent threads for scanning (default: 10)", defaultValue = "10")
    int concurrency;

    @Option(names = {"--gateway-type"}, description = "Gateway type: auto, traefik, kong, spring-cloud-gateway, k8s", defaultValue = "auto")
    String gatewayType;

    @Option(names = {"--app-url"}, description = "Public Application URL for Gateway Discovery (e.g. http://myapp.com)")
    String appUrl;

    @Option(names = {"--k8s-token"}, description = "Kubernetes ServiceAccount Token (or set K8S_TOKEN env var)")
    String k8sToken;

    @Override
    public Integer call() throws Exception {
        log.info("Starting CLI scan. Discoverer: {}, Target: {}", discovererId, target);

        SecurityScheme authScheme = null;
        if (bearerToken != null && !bearerToken.isEmpty()) {
            authScheme = SecurityScheme.bearer(bearerToken);
        }

        SecurityScheme secondaryAuthScheme = null;
        if (secondaryBearerToken != null && !secondaryBearerToken.isEmpty()) {
            secondaryAuthScheme = SecurityScheme.bearer(secondaryBearerToken);
        }

        // Handle OAuth2 automated token fetching
        if (oauth2Url != null && oauth2Grant != null) {
            log.info("Fetching OAuth2 tokens from {}", oauth2Url);
            OAuth2Config oauth2Config = new OAuth2Config(oauth2Url, oauth2ClientId, oauth2ClientSecret, oauth2Grant, oauth2Creds);
            List<SecurityScheme> fetchedTokens = tokenFetcher.fetchTokens(oauth2Config).block();
            
            if (fetchedTokens != null && !fetchedTokens.isEmpty()) {
                authScheme = fetchedTokens.get(0);
                if (fetchedTokens.size() > 1) {
                    secondaryAuthScheme = fetchedTokens.get(1);
                    log.info("Successfully fetched 2+ tokens. Primary and Secondary Auth mapped for BOLA testing.");
                } else {
                    log.info("Successfully fetched 1 token.");
                }
            } else {
                log.error("Failed to fetch any OAuth2 tokens. Proceeding without authentication.");
            }
        }

        ScanConfiguration config = new ScanConfiguration(
                includeScanners != null ? includeScanners : List.of(),
                excludeScanners != null ? excludeScanners : List.of(),
                concurrency,
                5000,
                10000,
                false,
                format,
                authScheme,
                secondaryAuthScheme,
                language,
                includePassed,
                GatewayType.fromString(gatewayType),
                appUrl,
                k8sToken
        );

        try {
            // Block until scan is complete because this is a CLI command
            java.time.Instant startTime = java.time.Instant.now();
            List<ch.nexsol.orthrusdast.model.ScanAttempt> attempts = scanService.executeScan(discovererId, target, overrideHost, config).collectList().block();
            
            if (attempts == null) {
                attempts = List.of();
            }

            int testsCount = attempts.size();
            List<ch.nexsol.orthrusdast.model.Vulnerability> vulnerabilities = attempts.stream()
                .filter(a -> a.vulnerabilities() != null)
                .flatMap(a -> a.vulnerabilities().stream())
                .sorted(java.util.Comparator.comparing(ch.nexsol.orthrusdast.model.Vulnerability::riskLevel).reversed())
                .toList();

            Map<ch.nexsol.orthrusdast.model.RiskLevel, Long> riskSummary = vulnerabilities.stream()
                .collect(Collectors.groupingBy(ch.nexsol.orthrusdast.model.Vulnerability::riskLevel, Collectors.counting()));
            Map<String, Integer> scannerSummary = vulnerabilities.stream()
                .collect(Collectors.groupingBy(ch.nexsol.orthrusdast.model.Vulnerability::scannerId, Collectors.collectingAndThen(Collectors.counting(), Long::intValue)));

            ScanResult result = new ScanResult(
                java.util.UUID.randomUUID().toString(),
                target,
                startTime,
                java.time.Instant.now(),
                0,
                testsCount,
                vulnerabilities,
                riskSummary,
                scannerSummary,
                config,
                attempts
            );

            ReportGenerator generator = reportGenerators.get(format.toLowerCase());
            if (generator == null) {
                log.warn("Unknown format '{}'. Falling back to console.", format);
                generator = reportGenerators.get("console");
            }

            OutputStream os = System.out;
            if (outputFile != null && !outputFile.isEmpty()) {
                os = new FileOutputStream(outputFile);
            }

            generator.generateReport(result, os).block();

            if (os != System.out) {
                os.close();
            }

            // Return non-zero exit code if vulnerabilities found (useful for CI/CD)
            return result.vulnerabilities().isEmpty() ? 0 : 1;

        } catch (Exception e) {
            log.error("Scan failed", e);
            return 2;
        }
    }
}

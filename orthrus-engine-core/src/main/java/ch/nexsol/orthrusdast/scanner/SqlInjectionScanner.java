package ch.nexsol.orthrusdast.scanner;

import java.util.List;

import ch.nexsol.orthrusdast.http.ScanHttpClient;
import ch.nexsol.orthrusdast.model.CWEReference;
import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.RiskLevel;
import ch.nexsol.orthrusdast.model.Vulnerability;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import java.util.Map;

/**
 * Scans for SQL Injection vulnerabilities (CWE-89).
 */
@Component
public class SqlInjectionScanner implements SecurityScanner {

    private static final Logger log = LoggerFactory.getLogger(SqlInjectionScanner.class);
    private final ScanHttpClient httpClient;
    private final ch.nexsol.orthrusdast.scanner.payload.PayloadLoaderService payloadLoader;
    private final ch.nexsol.orthrusdast.scanner.payload.PayloadMutator payloadMutator;
    private final ch.nexsol.orthrusdast.scanner.oast.OastService oastService;

    public SqlInjectionScanner(ScanHttpClient httpClient, 
                               ch.nexsol.orthrusdast.scanner.payload.PayloadLoaderService payloadLoader,
                               ch.nexsol.orthrusdast.scanner.payload.PayloadMutator payloadMutator,
                               ch.nexsol.orthrusdast.scanner.oast.OastService oastService) {
        this.httpClient = httpClient;
        this.payloadLoader = payloadLoader;
        this.payloadMutator = payloadMutator;
        this.oastService = oastService;
    }

    @Override
    public String getId() {
        return "sqli";
    }

    @Override
    public String getName() {
        return "SQL Injection Scanner";
    }

    @Override
    public Flux<Vulnerability> scan(Operation operation) {
        return Flux.defer(() -> {
        log.debug("Scanning for SQL Injection: {}", operation.url());

        return oastService.createSession().flatMapMany(oastSession -> {
            Flux<Vulnerability> scanVulns = Flux.empty();

            scanVulns = payloadLoader.getPayloads("sqli")
                    .concatMap(rawPayload -> {
                        String oastPayload = rawPayload.replace("{{OAST_HOST}}", oastSession.domain());
                        String payload = payloadMutator.mutate(oastPayload, ch.nexsol.orthrusdast.scanner.payload.PayloadMutator.Context.URL_PARAM);
                        return InjectionHelper.generateInjectedOperations(operation, payload)
                                .concatMap(test -> executeSqlInjectionTest(operation, test.mutatedOperation(), test.injectionPoint(), payload));
                    });

            return scanVulns.concatWith(oastService.pollInteractions(oastSession).map(interaction -> 
                createVulnerabilityWithTrace(
                    "Out-Of-Band (Blind) SQL Injection",
                    "The endpoint triggered a DNS/HTTP request to the OAST server during SQL injection payload execution.",
                    RiskLevel.CRITICAL,
                    Vulnerability.Confidence.HIGH,
                    operation,
                    CWEReference.CWE_89,
                    List.of("CAPEC-66"),
                    9.8,
                    "An interaction was received from " + interaction.remoteAddress() + " via " + interaction.protocol() + " for query: " + interaction.queryType(),
                    "Use parameterized queries or prepared statements.", operation, null,
                    "API Endpoint (Network)",
                    "Unauthorized Access / Data Exposure"
                )
            ));
        });
            });
    }
    
    private Flux<Vulnerability> executeSqlInjectionTest(Operation originalOp, Operation testOp, String injectionPoint, String payload) {
        return httpClient.send(testOp)
                .flatMapMany(response -> {
                    // Time-Based Blind Detection (Duration > 4000ms)
                    if (response.responseTimeMs() > 4000) {
                        Vulnerability vuln = createVulnerabilityWithTrace(
                            "Time-Based Blind SQL Injection",
                            "The endpoint took " + response.responseTimeMs() + "ms to respond, indicating a potential Time-Based Blind SQL Injection in " + injectionPoint + ".",
                            RiskLevel.CRITICAL,
                            Vulnerability.Confidence.HIGH,
                            originalOp,
                            CWEReference.CWE_89,
                            List.of("CAPEC-66"),
                            9.8,
                            "Response was delayed by " + response.responseTimeMs() + "ms when payload '" + payload + "' was injected.",
                            "Use parameterized queries or prepared statements.",
                            testOp,
                            response,
                            "API Endpoint (Network)",
                            "Unauthorized Access / Data Exposure");
                        return Flux.just(vuln);
                    }

                    // Content-Based Detection (SQL Errors)
                    String bodyLower = response.body() != null ? response.body().toLowerCase() : "";
                    boolean hasSqlError = bodyLower.contains("syntax error") ||
                                          bodyLower.contains("mysql_fetch") ||
                                          bodyLower.contains("you have an error in your sql syntax") ||
                                          bodyLower.contains("ora-") ||
                                          bodyLower.contains("postgresql") ||
                                          bodyLower.contains("java.sql.sqlexception") ||
                                          bodyLower.contains("sqlite/m");

                    if (hasSqlError) {
                        Vulnerability vuln = createVulnerabilityWithTrace(
                            "Potential Error-Based SQL Injection",
                            "The endpoint might be vulnerable to Error-Based SQL Injection in " + injectionPoint + ".",
                            RiskLevel.HIGH,
                            Vulnerability.Confidence.MEDIUM,
                            originalOp,
                            CWEReference.CWE_89,
                            List.of("CAPEC-66"),
                            9.8,
                            "Response indicates a database error when payload '" + payload + "' was injected.",
                            "Use parameterized queries or prepared statements and disable verbose error messages.",
                            testOp,
                            response,
                            "API Endpoint (Network)",
                            "Unauthorized Access / Data Exposure");
                        return Flux.just(vuln);
                    }
                    return Flux.empty();
                });
    }

    private String truncate(String text) {
        if (text == null) return "null";
        return text.length() > 200 ? text.substring(0, 200) + "..." : text;
    }
}

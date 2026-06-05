package ch.nexsol.orthrusdast.scanner;

import java.util.List;

import ch.nexsol.orthrusdast.http.ScanHttpClient;
import ch.nexsol.orthrusdast.model.CWEReference;
import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.RiskLevel;
import ch.nexsol.orthrusdast.model.Vulnerability;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;

import java.util.HashMap;
import java.util.Map;

/**
 * Scans for Cross-Site Scripting (XSS) (CWE-79).
 */
@Component
public class XssScanner implements SecurityScanner {

    private static final Logger log = LoggerFactory.getLogger(XssScanner.class);
    private final ScanHttpClient httpClient;
    private final ObjectMapper mapper = new ObjectMapper();
    private final ch.nexsol.orthrusdast.scanner.payload.PayloadLoaderService payloadLoader;
    private final ch.nexsol.orthrusdast.scanner.payload.PayloadMutator payloadMutator;
    private final ch.nexsol.orthrusdast.scanner.oast.OastService oastService;

    public XssScanner(ScanHttpClient httpClient, 
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
        return "xss";
    }

    @Override
    public String getName() {
        return "Cross-Site Scripting (XSS) Scanner";
    }

    @Override
    public Flux<Vulnerability> scan(Operation operation) {
        return oastService.createSession().flatMapMany(oastSession -> {
            
            Flux<Vulnerability> scanVulns = payloadLoader.getPayloads("xss").concatMap(rawPayload -> {
                String oastPayload = rawPayload.replace("{{OAST_HOST}}", oastSession.domain());
                String payload = payloadMutator.mutate(oastPayload, ch.nexsol.orthrusdast.scanner.payload.PayloadMutator.Context.URL_PARAM);
                
                return InjectionHelper.generateInjectedOperations(operation, payload)
                        .concatMap(test -> executeAndCheck(test.mutatedOperation(), operation, test.injectionPoint(), payload));
            }).take(1);
            
            return scanVulns.concatWith(oastService.pollInteractions(oastSession).map(interaction -> 
                createVulnerabilityWithTrace(
                    "Out-Of-Band (Blind) XSS",
                    "The endpoint triggered an out-of-band request to the OAST server, indicating a Blind XSS vulnerability.",
                    RiskLevel.CRITICAL,
                    Vulnerability.Confidence.HIGH,
                    operation,
                    CWEReference.CWE_79,
                    List.of("CAPEC-63"),
                    9.8,
                    "An interaction was received from " + interaction.remoteAddress() + " via " + interaction.protocol() + " for query: " + interaction.queryType(),
                    "Contextually encode user input before reflecting it in nulls, even in internal administrative dashboards.", operation, null,
                    "API Endpoint (Network)",
                    "Unauthorized Access / Data Exposure"
                )
            ));
        });
    }

    private Flux<Vulnerability> executeAndCheck(Operation testOp, Operation originalOp, String injectionPoint, String payload) {
        return httpClient.send(testOp)
                .flatMapMany(response -> {
                    if (response.bodyContainsExact(payload)) {
                        String contentType = response.getHeader("Content-Type");
                        boolean isHtml = contentType != null && contentType.toLowerCase().contains("text/html");
                        
                        // Basic context detection: if it's HTML, check if characters like '<', '>', or '"' are present and unescaped
                        boolean isUnescaped = payload.contains("<") && response.bodyContainsExact("<") || 
                                              payload.contains("\"") && response.bodyContainsExact("\"");
                        
                        if (!isUnescaped) {
                            // If the payload was safely HTML-encoded (e.g. &lt;), it's not a direct vulnerability
                            return Flux.empty();
                        }

                        RiskLevel risk = isHtml ? RiskLevel.HIGH : RiskLevel.MEDIUM;
                        String severityContext = isHtml ? "The response is served as HTML, meaning a browser will execute this script directly." 
                                                      : "The response is not HTML, so the script won't execute directly in modern browsers, but could be dangerous if a frontend incorrectly inserts this JSON data into the DOM.";
                        
                        Vulnerability vuln = createVulnerabilityWithTrace(
                                "Reflected Cross-Site Scripting (XSS)",
                                "The endpoint reflects unencoded user input from " + injectionPoint + " into the response.",
                                risk,
                                Vulnerability.Confidence.HIGH,
                                originalOp,
                                CWEReference.CWE_79,
                                List.of("CAPEC-63"),
                                6.1,
                                "Response contains the exact unencoded XSS payload. " + severityContext,
                                "Contextually encode user input before reflecting it in responses. Ensure the Content-Type header is strictly set to application/json for APIs.",
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

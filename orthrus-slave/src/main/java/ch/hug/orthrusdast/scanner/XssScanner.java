package ch.hug.orthrusdast.scanner;

import java.util.List;

import ch.hug.orthrusdast.http.ScanHttpClient;
import ch.hug.orthrusdast.model.CWEReference;
import ch.hug.orthrusdast.model.Operation;
import ch.hug.orthrusdast.model.RiskLevel;
import ch.hug.orthrusdast.model.Vulnerability;
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
    private final ch.hug.orthrusdast.scanner.payload.PayloadLoaderService payloadLoader;
    private final ch.hug.orthrusdast.scanner.payload.PayloadMutator payloadMutator;
    private final ch.hug.orthrusdast.scanner.oast.OastService oastService;

    public XssScanner(ScanHttpClient httpClient, 
                      ch.hug.orthrusdast.scanner.payload.PayloadLoaderService payloadLoader,
                      ch.hug.orthrusdast.scanner.payload.PayloadMutator payloadMutator,
                      ch.hug.orthrusdast.scanner.oast.OastService oastService) {
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
            Flux<Vulnerability> queryVulns = testQueryParams(operation, oastSession);
            Flux<Vulnerability> headerVulns = testHeaders(operation, oastSession);
            Flux<Vulnerability> bodyVulns = testJsonBody(operation, oastSession);
            
            return Flux.concat(queryVulns, headerVulns, bodyVulns)
                    .concatWith(oastService.pollInteractions(oastSession).map(interaction -> 
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

    private Flux<Vulnerability> testQueryParams(Operation operation, ch.hug.orthrusdast.scanner.oast.OastService.OastSession oastSession) {
        if (operation.queryParams() != null && !operation.queryParams().isEmpty()) {
            return Flux.fromIterable(operation.queryParams().keySet())
                    .concatMap(paramName -> 
                        payloadLoader.getPayloads("xss").concatMap(rawPayload -> {
                            String oastPayload = rawPayload.replace("{{OAST_HOST}}", oastSession.domain());
                            String payload = payloadMutator.mutate(oastPayload, ch.hug.orthrusdast.scanner.payload.PayloadMutator.Context.URL_PARAM);

                            Map<String, String> modifiedParams = new HashMap<>(operation.queryParams());
                            modifiedParams.put(paramName, payload);
                            
                            Operation testOp = new Operation(
                                    operation.url(),
                                    operation.method(),
                                    operation.headers(),
                                    modifiedParams,
                                    operation.body(),
                                    operation.securityRequirements(),
                                    operation.expectedContentTypes(),
                                    operation.authScheme()
                            );
                            return executeAndCheck(testOp, operation, "query param", paramName, payload);
                        })
                    );
        }
        return Flux.empty();
    }
    
    private Flux<Vulnerability> testHeaders(Operation operation, ch.hug.orthrusdast.scanner.oast.OastService.OastSession oastSession) {
        // Inject into common headers
        String[] targetHeaders = {"User-Agent", "Referer", "X-Forwarded-For"};
        return Flux.fromArray(targetHeaders)
                .concatMap(headerName -> 
                    payloadLoader.getPayloads("xss").concatMap(rawPayload -> {
                        String oastPayload = rawPayload.replace("{{OAST_HOST}}", oastSession.domain());
                        String payload = payloadMutator.mutate(oastPayload, ch.hug.orthrusdast.scanner.payload.PayloadMutator.Context.HEADER);

                        Map<String, String> modifiedHeaders = new HashMap<>();
                        if (operation.headers() != null) {
                            modifiedHeaders.putAll(operation.headers());
                        }
                        modifiedHeaders.put(headerName, payload);
                        
                        Operation testOp = new Operation(
                                operation.url(),
                                operation.method(),
                                modifiedHeaders,
                                operation.queryParams(),
                                operation.body(),
                                operation.securityRequirements(),
                                operation.expectedContentTypes(),
                                operation.authScheme()
                        );
                        return executeAndCheck(testOp, operation, "header", headerName, payload);
                    })
                );
    }

    private Flux<Vulnerability> testJsonBody(Operation operation, ch.hug.orthrusdast.scanner.oast.OastService.OastSession oastSession) {
        if (operation.body() == null || operation.body().isEmpty() || !operation.body().trim().startsWith("{")) {
            return Flux.empty();
        }
        
        return payloadLoader.getPayloads("xss").concatMap(rawPayload -> {
            String oastPayload = rawPayload.replace("{{OAST_HOST}}", oastSession.domain());
            String payload = payloadMutator.mutate(oastPayload, ch.hug.orthrusdast.scanner.payload.PayloadMutator.Context.JSON_BODY);

            try {
                ObjectNode jsonBody = (ObjectNode) mapper.readTree(operation.body());
                
                // To be simple, we just inject the payload into a new root-level field
                jsonBody.put("xss_test_field", payload);
                String modifiedBody = mapper.writeValueAsString(jsonBody);
                
                Operation testOp = new Operation(
                        operation.url(),
                        operation.method(),
                        operation.headers(),
                        operation.queryParams(),
                        modifiedBody,
                        operation.securityRequirements(),
                        operation.expectedContentTypes(),
                        operation.authScheme()
                );
                return executeAndCheck(testOp, operation, "JSON body", "xss_test_field", payload);
                
            } catch (Exception e) {
                return Flux.empty();
            }
        });
    }

    private Flux<Vulnerability> executeAndCheck(Operation testOp, Operation originalOp, String location, String fieldName, String payload) {
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
                                "The endpoint reflects unencoded user input from " + location + " '" + fieldName + "' into the response.",
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

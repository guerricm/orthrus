package ch.hug.vulnapi.scanner;
import java.util.List;

import ch.hug.vulnapi.http.ScanHttpClient;
import ch.hug.vulnapi.model.CWEReference;
import ch.hug.vulnapi.model.Operation;
import ch.hug.vulnapi.model.RiskLevel;
import ch.hug.vulnapi.model.Vulnerability;
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
    private static final String PAYLOAD = "<script>alert('XSS_VULNAPI_TEST')</script>";

    public XssScanner(ScanHttpClient httpClient) {
        this.httpClient = httpClient;
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
        Flux<Vulnerability> queryVulns = testQueryParams(operation);
        Flux<Vulnerability> headerVulns = testHeaders(operation);
        Flux<Vulnerability> bodyVulns = testJsonBody(operation);
        
        return Flux.concat(queryVulns, headerVulns, bodyVulns);
    }

    private Flux<Vulnerability> testQueryParams(Operation operation) {
        if (operation.queryParams() != null && !operation.queryParams().isEmpty()) {
            return Flux.fromIterable(operation.queryParams().keySet())
                    .flatMap(paramName -> {
                        Map<String, String> modifiedParams = new HashMap<>(operation.queryParams());
                        modifiedParams.put(paramName, PAYLOAD);
                        
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
                        return executeAndCheck(testOp, operation, "query param", paramName);
                    });
        }
        return Flux.empty();
    }
    
    private Flux<Vulnerability> testHeaders(Operation operation) {
        // Inject into common headers
        String[] targetHeaders = {"User-Agent", "Referer", "X-Forwarded-For"};
        return Flux.fromArray(targetHeaders)
                .flatMap(headerName -> {
                    Map<String, String> modifiedHeaders = new HashMap<>();
                    if (operation.headers() != null) {
                        modifiedHeaders.putAll(operation.headers());
                    }
                    modifiedHeaders.put(headerName, PAYLOAD);
                    
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
                    return executeAndCheck(testOp, operation, "header", headerName);
                });
    }

    private Flux<Vulnerability> testJsonBody(Operation operation) {
        if (operation.body() == null || operation.body().isEmpty() || !operation.body().trim().startsWith("{")) {
            return Flux.empty();
        }
        
        try {
            ObjectNode jsonBody = (ObjectNode) mapper.readTree(operation.body());
            
            // To be simple, we just inject the payload into a new root-level field
            jsonBody.put("xss_test_field", PAYLOAD);
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
            return executeAndCheck(testOp, operation, "JSON body", "xss_test_field");
            
        } catch (Exception e) {
            return Flux.empty();
        }
    }

    private Flux<Vulnerability> executeAndCheck(Operation testOp, Operation originalOp, String location, String fieldName) {
        return httpClient.send(testOp)
                .flatMapMany(response -> {
                    if (response.bodyContainsExact(PAYLOAD)) {
                        String contentType = response.getHeader("Content-Type");
                        boolean isHtml = contentType != null && contentType.toLowerCase().contains("text/html");
                        
                        RiskLevel risk = isHtml ? RiskLevel.HIGH : RiskLevel.MEDIUM;
                        String severityContext = isHtml ? "The response is served as HTML, meaning a browser will execute this script directly." 
                                                      : "The response is not HTML, so the script won't execute directly in modern browsers, but could be dangerous if a frontend incorrectly inserts this JSON data into the DOM.";
                        
                        Vulnerability vuln = Vulnerability.createWithDetails(
                                "Reflected Cross-Site Scripting (XSS)",
                                "The endpoint reflects unencoded user input from " + location + " '" + fieldName + "' into the response.",
                                risk,
                                Vulnerability.Confidence.HIGH,
                                getId(),
                                originalOp,
                                CWEReference.CWE_79,
                                "Injection",
                                List.of("CAPEC-63"),
                                6.1,
                                "Response contains the exact unencoded XSS payload. " + severityContext,
                                "Contextually encode user input before reflecting it in responses. Ensure the Content-Type header is strictly set to application/json for APIs.",
                                "Injected XSS payload into " + location + ": " + fieldName + "=" + PAYLOAD,
                                "Status: " + response.statusCode() + "\nContent-Type: " + contentType + "\nBody snippet: " + truncate(response.body())
                        );
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

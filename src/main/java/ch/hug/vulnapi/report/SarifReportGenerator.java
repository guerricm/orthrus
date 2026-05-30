package ch.hug.vulnapi.report;

import ch.hug.vulnapi.model.ScanResult;
import ch.hug.vulnapi.model.Vulnerability;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.io.OutputStream;

/**
 * Generates a report in SARIF (Static Analysis Results Interchange Format)
 * for integration with CI/CD tools like GitHub Advanced Security.
 */
@Component
public class SarifReportGenerator implements ReportGenerator {

    private static final Logger log = LoggerFactory.getLogger(SarifReportGenerator.class);
    private final ObjectMapper mapper = new ObjectMapper();

    @Override
    public String getFormat() {
        return "sarif";
    }

    @Override
    public Mono<Void> generateReport(ScanResult result, OutputStream output) {
         return Mono.fromRunnable(() -> {
            try {
                ObjectNode root = mapper.createObjectNode();
                root.put("version", "2.1.0");
                root.put("$schema", "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json");

                ArrayNode runs = root.putArray("runs");
                ObjectNode run = runs.addObject();

                ObjectNode tool = run.putObject("tool");
                ObjectNode driver = tool.putObject("driver");
                driver.put("name", "Orthrus VulnAPI");
                driver.put("informationUri", "https://github.com/cerberauth/vulnapi");
                driver.put("version", "1.0.0");

                // We need to define rules for each scanner/CWE
                ArrayNode rules = driver.putArray("rules");
                ArrayNode results = run.putArray("results");

                for (Vulnerability v : result.vulnerabilities()) {
                    // Add rule if not exists (simplified here by just adding it, real implementation would deduplicate)
                    ObjectNode rule = rules.addObject();
                    rule.put("id", v.cwe().getCweId());
                    rule.putObject("shortDescription").put("text", v.cwe().getName());
                    rule.putObject("fullDescription").put("text", v.description());

                    // Add result
                    ObjectNode res = results.addObject();
                    res.put("ruleId", v.cwe().getCweId());
                    
                    String sarifLevel = switch (v.riskLevel()) {
                        case CRITICAL, HIGH -> "error";
                        case MEDIUM -> "warning";
                        case LOW, INFO -> "note";
                    };
                    res.put("level", sarifLevel);
                    
                    res.putObject("message").put("text", v.name() + ": " + v.evidence());
                    
                    ArrayNode locations = res.putArray("locations");
                    ObjectNode location = locations.addObject();
                    ObjectNode physicalLocation = location.putObject("physicalLocation");
                    ObjectNode artifactLocation = physicalLocation.putObject("artifactLocation");
                    // SARIF usually expects a file path, we map the URL to the uri
                    artifactLocation.put("uri", v.operationUrl());
                }

                mapper.writerWithDefaultPrettyPrinter().writeValue(output, root);
            } catch (Exception e) {
                log.error("Failed to generate SARIF report", e);
                throw new RuntimeException("SARIF generation failed", e);
            }
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }
}

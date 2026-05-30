package ch.hug.vulnapi.report;

import ch.hug.vulnapi.model.ScanResult;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.io.OutputStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;

/**
 * Generates a simple HTML report.
 */
@Component
public class HtmlReportGenerator implements ReportGenerator {

    @Override
    public String getFormat() {
        return "html";
    }

    @Override
    public Mono<Void> generateReport(ScanResult result, OutputStream output) {
        return Mono.fromRunnable(() -> {
            try (PrintWriter writer = new PrintWriter(output, true, StandardCharsets.UTF_8)) {
                writer.println("<!DOCTYPE html>");
                writer.println("<html>");
                writer.println("<head><title>Orthrus VulnAPI Report</title>");
                writer.println("<style>");
                writer.println("body { font-family: Arial, sans-serif; margin: 40px; }");
                writer.println(".critical { color: white; background-color: #d9534f; padding: 3px 6px; border-radius: 3px; }");
                writer.println(".high { color: white; background-color: #f0ad4e; padding: 3px 6px; border-radius: 3px; }");
                writer.println(".medium { color: black; background-color: #fcf8e3; padding: 3px 6px; border-radius: 3px; border: 1px solid #faebcc; }");
                writer.println(".low { color: black; background-color: #d9edf7; padding: 3px 6px; border-radius: 3px; border: 1px solid #bce8f1; }");
                writer.println(".vuln-card { border: 1px solid #ddd; padding: 15px; margin-bottom: 20px; border-radius: 5px; }");
                writer.println("pre { background: #f4f4f4; padding: 10px; overflow-x: auto; }");
                writer.println("</style>");
                writer.println("</head><body>");

                writer.println("<h1>Orthrus VulnAPI Scan Report</h1>");
                writer.println("<p><strong>Target:</strong> " + result.targetUrl() + "</p>");
                writer.println("<p><strong>Started:</strong> " + result.scanStartTime() + "</p>");
                writer.println("<p><strong>Vulnerabilities Found:</strong> " + result.vulnerabilities().size() + "</p>");
                
                writer.println("<h2>Risk Summary</h2><ul>");
                result.riskSummary().forEach((level, count) -> {
                    writer.println("<li><strong>" + level + ":</strong> " + count + "</li>");
                });
                writer.println("</ul>");

                writer.println("<h2>Details</h2>");
                if (result.vulnerabilities().isEmpty()) {
                    writer.println("<p>No vulnerabilities found! 🎉</p>");
                } else {
                    result.vulnerabilities().forEach(v -> {
                        writer.println("<div class='vuln-card'>");
                        String cssClass = v.riskLevel().name().toLowerCase();
                        writer.println("<h3><span class='" + cssClass + "'>" + v.riskLevel() + "</span> " + v.name() + "</h3>");
                        writer.println("<p><strong>Endpoint:</strong> <code>" + v.operationMethod() + " " + v.operationUrl() + "</code></p>");
                        writer.println("<p><strong>CWE:</strong> " + v.cwe().getCweId() + " - " + v.cwe().getName() + "</p>");
                        writer.println("<p><strong>Description:</strong> " + v.description() + "</p>");
                        writer.println("<p><strong>Evidence:</strong> " + v.evidence() + "</p>");
                        writer.println("<p><strong>Remediation:</strong> " + v.remediation() + "</p>");
                        writer.println("<details><summary>Request Details</summary><pre>" + v.requestDetails() + "</pre></details>");
                        if (v.responseDetails() != null) {
                            writer.println("<details><summary>Response Details</summary><pre>" + v.responseDetails() + "</pre></details>");
                        }
                        writer.println("</div>");
                    });
                }

                writer.println("</body></html>");
            }
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }
}

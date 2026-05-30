package ch.hug.vulnapi.report;

import ch.hug.vulnapi.model.ScanResult;
import ch.hug.vulnapi.model.Vulnerability;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.io.OutputStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;

/**
 * Prints a summary report to the console.
 */
@Component
public class ConsoleReportGenerator implements ReportGenerator {

    // ANSI escape codes for colors
    private static final String ANSI_RESET = "\u001B[0m";
    private static final String ANSI_RED = "\u001B[31m";
    private static final String ANSI_YELLOW = "\u001B[33m";
    private static final String ANSI_CYAN = "\u001B[36m";

    @Override
    public String getFormat() {
        return "console";
    }

    @Override
    public Mono<Void> generateReport(ScanResult result, OutputStream output) {
         return Mono.fromRunnable(() -> {
            try (PrintWriter writer = new PrintWriter(output, true, StandardCharsets.UTF_8)) {
                
                writer.println();
                writer.println(ANSI_CYAN + "============================================================" + ANSI_RESET);
                writer.println(ANSI_CYAN + "                ORTHRUS VULNAPI SCAN SUMMARY                " + ANSI_RESET);
                writer.println(ANSI_CYAN + "============================================================" + ANSI_RESET);
                writer.println("Target:     " + result.targetUrl());
                writer.println("Operations: " + result.operationsDiscovered());
                writer.println("Duration:   " + java.time.Duration.between(result.scanStartTime(), result.scanEndTime()).toSeconds() + "s");
                writer.println("Total Vulns:" + (result.vulnerabilities().isEmpty() ? " 0 🎉" : " " + result.vulnerabilities().size()));
                writer.println();

                if (!result.vulnerabilities().isEmpty()) {
                    writer.println("RISK BREAKDOWN:");
                    result.riskSummary().forEach((level, count) -> {
                        if (count > 0) {
                            String color = switch (level) {
                                case CRITICAL, HIGH -> ANSI_RED;
                                case MEDIUM -> ANSI_YELLOW;
                                default -> ANSI_RESET;
                            };
                            writer.println("  " + color + level.name() + ": " + count + ANSI_RESET);
                        }
                    });
                    
                    writer.println();
                    writer.println("FINDINGS:");
                    for (int i = 0; i < result.vulnerabilities().size(); i++) {
                        Vulnerability v = result.vulnerabilities().get(i);
                        String color = switch (v.riskLevel()) {
                            case CRITICAL, HIGH -> ANSI_RED;
                            case MEDIUM -> ANSI_YELLOW;
                            default -> ANSI_RESET;
                        };
                        writer.println("  " + (i+1) + ". " + color + "[" + v.riskLevel() + "] " + v.name() + ANSI_RESET);
                        writer.println("     " + v.operationMethod() + " " + v.operationUrl());
                        writer.println("     " + v.cwe().getCweId());
                        writer.println();
                    }
                }
                writer.println(ANSI_CYAN + "============================================================" + ANSI_RESET);
            }
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }
}

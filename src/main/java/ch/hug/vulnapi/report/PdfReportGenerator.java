package ch.hug.vulnapi.report;

import ch.hug.vulnapi.model.RiskLevel;
import ch.hug.vulnapi.model.ScanResult;
import ch.hug.vulnapi.model.Vulnerability;
import com.openhtmltopdf.pdfboxout.PdfRendererBuilder;
import org.springframework.stereotype.Component;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;
import reactor.core.publisher.Mono;

import java.io.OutputStream;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;

@Component
public class PdfReportGenerator implements ReportGenerator {

    private final TemplateEngine templateEngine;

    public PdfReportGenerator(TemplateEngine templateEngine) {
        this.templateEngine = templateEngine;
    }

    @Override
    public String getFormat() {
        return "pdf";
    }

    @Override
    public Mono<Void> generateReport(ScanResult result, OutputStream outputStream) {
        return Mono.fromRunnable(() -> {
            try {
                // 1. Determine Language
                String langStr = result.configuration() != null && result.configuration().language() != null
                        ? result.configuration().language() : "en";
                Locale locale = Locale.forLanguageTag(langStr);

                // 2. Prepare Context for Thymeleaf
                Context context = new Context(locale);

                // Date Formatting
                DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());
                context.setVariable("scanDate", formatter.format(result.scanStartTime()));
                context.setVariable("targetUrl", result.targetUrl());

                // Sort Vulnerabilities by RiskLevel (CRITICAL first, INFO last)
                List<Vulnerability> sortedVulns = result.vulnerabilities().stream()
                        .sorted(Comparator.comparing(Vulnerability::riskLevel).reversed())
                        .collect(Collectors.toList());
                context.setVariable("vulnerabilities", sortedVulns);

                // Stats
                long critical = result.riskSummary().getOrDefault(RiskLevel.CRITICAL, 0L);
                long high = result.riskSummary().getOrDefault(RiskLevel.HIGH, 0L);
                long medium = result.riskSummary().getOrDefault(RiskLevel.MEDIUM, 0L);
                long low = result.riskSummary().getOrDefault(RiskLevel.LOW, 0L);
                long info = result.riskSummary().getOrDefault(RiskLevel.INFO, 0L);

                context.setVariable("totalVulns", result.vulnerabilities().size());
                context.setVariable("countCritical", critical);
                context.setVariable("countHigh", high);
                context.setVariable("countMedium", medium);
                context.setVariable("countLow", low);
                context.setVariable("countInfo", info);

                // 3. Calculate Global Grade
                String grade = "A";
                if (critical > 0) grade = "F";
                else if (high > 0) grade = "D";
                else if (medium > 0) grade = "C";
                else if (low > 0) grade = "B";
                context.setVariable("globalGrade", grade);

                // 4. Render HTML
                String html = templateEngine.process("report", context);

                // 5. Generate PDF
                PdfRendererBuilder builder = new PdfRendererBuilder();
                builder.useFastMode();
                builder.withHtmlContent(html, "");
                builder.toStream(outputStream);
                builder.run();

            } catch (Exception e) {
                throw new RuntimeException("Failed to generate PDF report", e);
            }
        });
    }
}

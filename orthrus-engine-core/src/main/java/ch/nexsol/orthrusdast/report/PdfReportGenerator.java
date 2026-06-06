package ch.nexsol.orthrusdast.report;

import ch.nexsol.orthrusdast.model.RiskLevel;
import ch.nexsol.orthrusdast.model.ScanResult;
import ch.nexsol.orthrusdast.model.Vulnerability;
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

/**
 * Generates a PDF report using Thymeleaf and OpenHTMLToPDF.
 * 
 * This generator uses a pre-defined Thymeleaf template (the same as the HTML
 * generator)
 * to produce a styled HTML string, which is then converted into a PDF document
 * containing
 * vulnerability summaries, details, and optionally, full execution logs.
 */
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

    /**
     * Generates a PDF report from a ScanResult and writes it to the output stream.
     *
     * @param result       the scan result containing vulnerabilities and execution
     *                     attempts
     * @param outputStream the output stream to write the PDF content to
     * @return a Mono signaling completion
     */
    @Override
    public Mono<Void> generateReport(ScanResult result, OutputStream outputStream) {
        return Mono.fromRunnable(() -> {
            try {
                // 1. Determine Language
                String langStr = result.configuration() != null && result.configuration().language() != null
                        ? result.configuration().language()
                        : "en";
                Locale locale = Locale.forLanguageTag(langStr);

                // 2. Prepare Context for Thymeleaf
                Context context = new Context(locale);

                // Date Formatting
                DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
                        .withZone(ZoneId.systemDefault());
                context.setVariable("scanDate", formatter.format(result.scanStartTime()));
                context.setVariable("targetUrl", result.targetUrl());
                context.setVariable("config", result.configuration());

                // Vulnerabilities are already sorted by ScanEngine
                context.setVariable("vulnerabilities", result.vulnerabilities());

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
                if (critical > 0)
                    grade = "F";
                else if (high > 0)
                    grade = "D";
                else if (medium > 0)
                    grade = "C";
                else if (low > 0)
                    grade = "B";
                context.setVariable("globalGrade", grade);

                // 4. Execution Details (if --include-passed)
                if (result.attempts() != null && !result.attempts().isEmpty()) {
                    java.util.LinkedHashMap<String, java.util.List<ch.nexsol.orthrusdast.model.ScanAttempt>> grouped = new java.util.LinkedHashMap<>();
                    for (ch.nexsol.orthrusdast.model.ScanAttempt a : result.attempts()) {
                        String key = a.operationMethod() + " " + a.operationUrl();
                        grouped.computeIfAbsent(key, k -> new java.util.ArrayList<>()).add(a);
                    }

                    java.util.List<ch.nexsol.orthrusdast.model.EndpointAttemptGroup> attemptGroupsList = new java.util.ArrayList<>();
                    for (java.util.Map.Entry<String, java.util.List<ch.nexsol.orthrusdast.model.ScanAttempt>> entry : grouped.entrySet()) {
                        long passed = entry.getValue().stream().filter(a -> ch.nexsol.orthrusdast.model.AttemptStatus.PASSED == a.status()).count();
                        long failed = entry.getValue().stream().filter(a -> ch.nexsol.orthrusdast.model.AttemptStatus.FAILED == a.status()).count();
                        long authError = entry.getValue().stream().filter(a -> ch.nexsol.orthrusdast.model.AttemptStatus.AUTH_ERROR == a.status()).count();
                        long error = entry.getValue().stream().filter(a -> ch.nexsol.orthrusdast.model.AttemptStatus.ERROR == a.status()).count();
                        attemptGroupsList.add(new ch.nexsol.orthrusdast.model.EndpointAttemptGroup(entry.getKey(),
                                entry.getValue(), passed, failed, authError, error));
                    }
                    context.setVariable("attemptGroups", attemptGroupsList);
                }

                context.setVariable("formatter", new ReportFormatter());

                // 5. Render HTML
                String html = templateEngine.process("report", context);

                // 6. Generate PDF
                PdfRendererBuilder builder = new PdfRendererBuilder();
                builder.withHtmlContent(html, "");
                builder.toStream(outputStream);
                builder.run();

            } catch (Exception e) {
                throw new RuntimeException("Failed to generate PDF report", e);
            }
        }).subscribeOn(reactor.core.scheduler.Schedulers.boundedElastic()).then();
    }

    public static class ReportFormatter {
        public String nl2br(String text) {
            if (text == null) return "";
            return org.springframework.web.util.HtmlUtils.htmlEscape(text).replace("\n", "<br/>");
        }

        public String truncateUrl(String url) {
            if (url == null) return "";
            if (url.length() > 100) {
                return url.substring(0, 100) + "...[TRUNCATED]";
            }
            return url;
        }
    }
}

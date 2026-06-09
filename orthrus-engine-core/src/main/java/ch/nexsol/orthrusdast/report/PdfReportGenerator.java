/*
 * Copyright 2014-2024 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package ch.nexsol.orthrusdast.report;

import java.io.InputStream;
import java.io.OutputStream;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Locale;

import org.springframework.stereotype.Component;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import com.openhtmltopdf.extend.FSSupplier;
import com.openhtmltopdf.outputdevice.helper.BaseRendererBuilder;
import com.openhtmltopdf.pdfboxout.PdfRendererBuilder;

import reactor.core.publisher.Mono;

import ch.nexsol.orthrusdast.model.RiskLevel;
import ch.nexsol.orthrusdast.model.ScanResult;

/**
 * Generates a PDF report using Thymeleaf and OpenHTMLToPDF.
 *
 * This generator uses a pre-defined Thymeleaf template (the same as the HTML generator)
 * to produce a styled HTML string, which is then converted into a PDF document containing
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
	 * @param result the scan result containing vulnerabilities and execution attempts
	 * @param outputStream the output stream to write the PDF content to
	 * @return a Mono signaling completion
	 */
	@Override
	public Mono<Void> generateReport(ScanResult result, OutputStream outputStream, boolean includePassed) {
		return Mono.fromRunnable(() -> {
			try {
				// 1. Determine Language
				String langStr = result.configuration() != null && result.configuration().language() != null
						? result.configuration().language() : "en";
				Locale locale = org.springframework.util.StringUtils.parseLocaleString(langStr);

				// 2. Prepare Context for Thymeleaf
				Context context = new Context(locale);

				// Date Formatting
				String pattern = "fr".equalsIgnoreCase(langStr) ? "dd.MM.yyyy" : "yyyy-MM-dd";
				DateTimeFormatter formatter = DateTimeFormatter.ofPattern(pattern).withZone(ZoneId.systemDefault());
				context.setVariable("scanDate", formatter.format(result.scanStartTime()));
				context.setVariable("targetUrl", result.targetUrl());
				context.setVariable("config", result.configuration());
				context.setVariable("discovererId", result.discovererId() != null ? result.discovererId() : "UNKNOWN");

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
				if (critical > 0) {
					grade = "F";
				}
				else if (high > 0) {
					grade = "D";
				}
				else if (medium > 0) {
					grade = "C";
				}
				else if (low > 0) {
					grade = "B";
				}
				context.setVariable("globalGrade", grade);

				// 4. Execution Details (if --include-passed)
				if (includePassed && result.attempts() != null && !result.attempts().isEmpty()) {
					java.util.LinkedHashMap<String, java.util.List<ch.nexsol.orthrusdast.model.ScanAttempt>> grouped = new java.util.LinkedHashMap<>();
					for (ch.nexsol.orthrusdast.model.ScanAttempt a : result.attempts()) {
						String key = a.operationMethod() + " " + a.operationUrl();
						grouped.computeIfAbsent(key, (k) -> new java.util.ArrayList<>()).add(a);
					}

					java.util.List<ch.nexsol.orthrusdast.model.EndpointAttemptGroup> attemptGroupsList = new java.util.ArrayList<>();
					for (java.util.Map.Entry<String, java.util.List<ch.nexsol.orthrusdast.model.ScanAttempt>> entry : grouped
						.entrySet()) {
						long passed = entry.getValue()
							.stream()
							.filter((a) -> ch.nexsol.orthrusdast.model.AttemptStatus.PASSED == a.status())
							.count();
						long failed = entry.getValue()
							.stream()
							.filter((a) -> ch.nexsol.orthrusdast.model.AttemptStatus.FAILED == a.status())
							.count();
						long authError = entry.getValue()
							.stream()
							.filter((a) -> ch.nexsol.orthrusdast.model.AttemptStatus.AUTH_ERROR == a.status())
							.count();
						long error = entry.getValue()
							.stream()
							.filter((a) -> ch.nexsol.orthrusdast.model.AttemptStatus.ERROR == a.status())
							.count();
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

				builder.useFont(new FSSupplier<InputStream>() {
					@Override
					public InputStream supply() {
						return PdfReportGenerator.class.getResourceAsStream("/fonts/Roboto-Regular.ttf");
					}
				}, "Roboto", 400, BaseRendererBuilder.FontStyle.NORMAL, true);

				builder.useFont(new FSSupplier<InputStream>() {
					@Override
					public InputStream supply() {
						return PdfReportGenerator.class.getResourceAsStream("/fonts/Roboto-Bold.ttf");
					}
				}, "Roboto", 700, BaseRendererBuilder.FontStyle.NORMAL, true);

				builder.withHtmlContent(html, "");
				builder.toStream(outputStream);
				builder.run();

			}
			catch (Exception ex) {
				throw new RuntimeException("Failed to generate PDF report", ex);
			}
		}).subscribeOn(reactor.core.scheduler.Schedulers.boundedElastic()).then();
	}

	public static class ReportFormatter {

		public String nl2br(String text) {
			if (text == null) {
				return "";
			}
			return org.springframework.web.util.HtmlUtils.htmlEscape(text).replace("\n", "<br/>");
		}

		public String truncateUrl(String url) {
			if (url == null) {
				return "";
			}
			if (url.length() > 100) {
				return url.substring(0, 100) + "...[TRUNCATED]";
			}
			return url;
		}

	}

}

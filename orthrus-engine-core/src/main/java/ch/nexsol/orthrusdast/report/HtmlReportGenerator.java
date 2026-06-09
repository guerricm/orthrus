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

import ch.nexsol.orthrusdast.model.RiskLevel;
import ch.nexsol.orthrusdast.model.ScanResult;
import org.springframework.stereotype.Component;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;
import reactor.core.publisher.Mono;

import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Locale;

/**
 * Generates an HTML report using Thymeleaf.
 *
 * This generator uses a pre-defined Thymeleaf template to produce a human-readable
 * security report containing vulnerability summaries, details, and optionally, full
 * execution logs of every scanner attempt.
 */
@Component
public class HtmlReportGenerator implements ReportGenerator {

	private final TemplateEngine templateEngine;

	public HtmlReportGenerator(TemplateEngine templateEngine) {
		this.templateEngine = templateEngine;
	}

	@Override
	public String getFormat() {
		return "html";
	}

	/**
	 * Generates an HTML report from a ScanResult and writes it to the output stream.
	 * @param result the scan result containing vulnerabilities and execution attempts
	 * @param output the output stream to write the HTML content to
	 * @return a Mono signaling completion
	 */
	@Override
	public Mono<Void> generateReport(ScanResult result, OutputStream output, boolean includePassed) {
		return Mono.fromRunnable(() -> {
			try {
				// 1. Determine Language
				String langStr = result.configuration() != null && result.configuration().language() != null
						? result.configuration().language() : "en";
				Locale locale = org.springframework.util.StringUtils.parseLocaleString(langStr);

				// 2. Prepare Context for Thymeleaf
				Context context = new Context(locale);

				// Date Formatting
				DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd.MM.yyyy HH:mm")
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

				context.setVariable("formatter", new PdfReportGenerator.ReportFormatter());

				// 5. Render HTML
				String html = templateEngine.process("report", context);

				// 6. Write HTML to output stream
				output.write(html.getBytes(StandardCharsets.UTF_8));
				output.flush();

			}
			catch (Exception e) {
				throw new RuntimeException("Failed to generate HTML report", e);
			}
		});
	}

}

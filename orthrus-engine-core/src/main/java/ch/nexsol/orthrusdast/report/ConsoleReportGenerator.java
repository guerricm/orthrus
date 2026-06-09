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

import java.io.OutputStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;

import org.springframework.stereotype.Component;

import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import ch.nexsol.orthrusdast.model.ScanResult;
import ch.nexsol.orthrusdast.model.Vulnerability;

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
	public Mono<Void> generateReport(ScanResult result, OutputStream output, boolean includePassed) {
		return Mono.fromRunnable(() -> {
			try (PrintWriter writer = new PrintWriter(output, true, StandardCharsets.UTF_8)) {

				writer.println();
				writer.println(ANSI_CYAN + "============================================================" + ANSI_RESET);
				writer.println(ANSI_CYAN + "                ORTHRUS VULNAPI SCAN SUMMARY                " + ANSI_RESET);
				writer.println(ANSI_CYAN + "============================================================" + ANSI_RESET);
				writer.println("Target:     " + result.targetUrl());
				writer.println("Operations: " + result.operationsDiscovered());
				writer.println("Duration:   "
						+ java.time.Duration.between(result.scanStartTime(), result.scanEndTime()).toSeconds() + "s");
				writer.println("Total Vulns:"
						+ (result.vulnerabilities().isEmpty() ? " 0 🎉" : " " + result.vulnerabilities().size()));
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
						writer.println(
								"  " + (i + 1) + ". " + color + "[" + v.riskLevel() + "] " + v.name() + ANSI_RESET);
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

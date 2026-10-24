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

package ch.nexsol.orthrusdast.web;

import java.io.ByteArrayOutputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import tools.jackson.databind.ObjectMapper;

import ch.nexsol.orthrusdast.engine.ScanResultService;
import ch.nexsol.orthrusdast.entity.ScanJobEntity;
import ch.nexsol.orthrusdast.entity.TestPlanEntity;
import ch.nexsol.orthrusdast.model.ScanConfiguration;
import ch.nexsol.orthrusdast.model.ScanResult;
import ch.nexsol.orthrusdast.report.HtmlReportGenerator;
import ch.nexsol.orthrusdast.report.PdfReportGenerator;
import ch.nexsol.orthrusdast.repository.ScanJobRepository;
import ch.nexsol.orthrusdast.repository.TestPlanRepository;

/**
 * HTML and PDF report downloads.
 */
@Controller
public class ReportController {

	private static final Logger log = LoggerFactory.getLogger(ReportController.class);

	private final ScanResultService scanResultService;

	private final ScanJobRepository scanJobRepository;

	private final TestPlanRepository testPlanRepository;

	private final PdfReportGenerator pdfReportGenerator;

	private final HtmlReportGenerator htmlReportGenerator;

	private final ObjectMapper objectMapper;

	public ReportController(ScanResultService scanResultService, ScanJobRepository scanJobRepository,
			TestPlanRepository testPlanRepository, PdfReportGenerator pdfReportGenerator,
			HtmlReportGenerator htmlReportGenerator, ObjectMapper objectMapper) {
		this.scanResultService = scanResultService;
		this.scanJobRepository = scanJobRepository;
		this.testPlanRepository = testPlanRepository;
		this.pdfReportGenerator = pdfReportGenerator;
		this.htmlReportGenerator = htmlReportGenerator;
		this.objectMapper = objectMapper;
	}

	@GetMapping(value = "/web/scans/{id}/html", produces = MediaType.TEXT_HTML_VALUE)
	public Mono<Void> getHtmlReport(@PathVariable String id, @RequestParam(defaultValue = "true") boolean includePassed,
			ServerWebExchange exchange) {
		return scanResultService.findById(id).flatMap((result) -> planNameOf(id).flatMap((planName) -> {
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			return htmlReportGenerator.generateReport(result, out, includePassed).then(Mono.defer(() -> {
				exchange.getResponse().setStatusCode(HttpStatus.OK);
				exchange.getResponse()
					.getHeaders()
					.add(HttpHeaders.CONTENT_DISPOSITION, "inline; filename=\""
							+ WebFormUtils.reportFilename(planName, result.targetUrl(), result.scanStartTime(), "html")
							+ "\"");
				DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(out.toByteArray());
				return exchange.getResponse().writeWith(Mono.just(buffer));
			}));
		})).then();
	}

	@GetMapping("/web/scans/{id}/pdf")
	public Mono<ResponseEntity<Resource>> downloadPdf(@PathVariable String id,
			@RequestParam(defaultValue = "false") boolean includePassed) {
		return scanResultService.findById(id)
			.flatMap((result) -> scanJobRepository.findByResultId(id)
				.flatMap((job) -> withConfiguration(result, job).zipWith(planNameOf(job), ReportInput::new))
				.defaultIfEmpty(new ReportInput(result, "")))
			.flatMap((input) -> {
				ByteArrayOutputStream out = new ByteArrayOutputStream();
				String filename = WebFormUtils.reportFilename(input.planName(), input.result().targetUrl(),
						input.result().scanStartTime(), "pdf");
				return pdfReportGenerator.generateReport(input.result(), out, includePassed)
					.then(Mono.fromCallable(() -> ResponseEntity.ok()
						.header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + filename + "\"")
						.contentType(MediaType.APPLICATION_PDF)
						.body((Resource) new ByteArrayResource(out.toByteArray()))));
			})
			.defaultIfEmpty(ResponseEntity.notFound().<Resource>build());
	}

	/**
	 * The result completed with the configuration its job ran, which the PDF renders in
	 * its execution conditions. Falls back to the bare result when the stored
	 * configuration no longer parses.
	 * @param result the stored result
	 * @param job the job that produced it
	 * @return the result to render
	 */
	private Mono<ScanResult> withConfiguration(ScanResult result, ScanJobEntity job) {
		return Mono.fromCallable(() -> {
			ScanConfiguration config = objectMapper.readValue(job.getScanConfigurationJson(), ScanConfiguration.class);
			return new ScanResult(result.id(), result.targetUrl(), result.scanStartTime(), result.scanEndTime(),
					result.operationsDiscovered(), result.operationsScanned(), result.vulnerabilities(),
					result.riskSummary(), result.scannerSummary(), config, result.attempts(), job.getDiscovererId());
		}).onErrorResume((e) -> {
			log.warn("Failed to parse configuration of job {}; generating the PDF without it", job.getId(), e);
			return Mono.just(result);
		});
	}

	/**
	 * The name of the plan a job ran, or an empty string for an ad-hoc scan or a deleted
	 * plan. Never completes empty, so it can be zipped with the result.
	 * @param job the job
	 * @return the plan name, or an empty string
	 */
	private Mono<String> planNameOf(ScanJobEntity job) {
		if (job.getTestPlanId() == null) {
			return Mono.just("");
		}
		return testPlanRepository.findById(job.getTestPlanId()).map(TestPlanEntity::getName).defaultIfEmpty("");
	}

	private Mono<String> planNameOf(String resultId) {
		return scanJobRepository.findByResultId(resultId).flatMap(this::planNameOf).defaultIfEmpty("");
	}

	/**
	 * What a PDF download renders and is named after.
	 */
	private record ReportInput(ScanResult result, String planName) {
	}

}

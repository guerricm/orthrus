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

import ch.nexsol.orthrusdast.engine.ScanResultService;
import ch.nexsol.orthrusdast.model.ScanConfiguration;
import ch.nexsol.orthrusdast.model.ScanResult;
import ch.nexsol.orthrusdast.report.HtmlReportGenerator;
import ch.nexsol.orthrusdast.report.PdfReportGenerator;
import ch.nexsol.orthrusdast.repository.ScanJobRepository;
import reactor.core.publisher.Mono;
import tools.jackson.databind.ObjectMapper;

/**
 * HTML and PDF report downloads.
 */
@Controller
public class ReportController {

	private static final Logger log = LoggerFactory.getLogger(ReportController.class);

	private final ScanResultService scanResultService;

	private final ScanJobRepository scanJobRepository;

	private final PdfReportGenerator pdfReportGenerator;

	private final HtmlReportGenerator htmlReportGenerator;

	private final ObjectMapper objectMapper;

	public ReportController(ScanResultService scanResultService, ScanJobRepository scanJobRepository,
			PdfReportGenerator pdfReportGenerator, HtmlReportGenerator htmlReportGenerator, ObjectMapper objectMapper) {
		this.scanResultService = scanResultService;
		this.scanJobRepository = scanJobRepository;
		this.pdfReportGenerator = pdfReportGenerator;
		this.htmlReportGenerator = htmlReportGenerator;
		this.objectMapper = objectMapper;
	}

	@GetMapping(value = "/web/scans/{id}/html", produces = MediaType.TEXT_HTML_VALUE)
	public Mono<Void> getHtmlReport(@PathVariable String id, @RequestParam(defaultValue = "true") boolean includePassed,
			ServerWebExchange exchange) {
		return scanResultService.findById(id).flatMap(result -> {
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			return htmlReportGenerator.generateReport(result, out, includePassed).then(Mono.defer(() -> {
				exchange.getResponse().setStatusCode(HttpStatus.OK);
				DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(out.toByteArray());
				return exchange.getResponse().writeWith(Mono.just(buffer));
			}));
		}).then();
	}

	@GetMapping("/web/scans/{id}/pdf")
	public Mono<ResponseEntity<Resource>> downloadPdf(@PathVariable String id,
			@RequestParam(defaultValue = "false") boolean includePassed) {
		return scanResultService.findById(id).flatMap(result -> scanJobRepository.findByResultId(id).map(job -> {
			try {
				ScanConfiguration config = objectMapper.readValue(job.getScanConfigurationJson(),
						ScanConfiguration.class);
				return new ScanResult(result.id(), result.targetUrl(), result.scanStartTime(), result.scanEndTime(),
						result.operationsDiscovered(), result.operationsScanned(), result.vulnerabilities(),
						result.riskSummary(), result.scannerSummary(), config, result.attempts(),
						job.getDiscovererId());
			}
			catch (Exception e) {
				log.warn("Failed to parse configuration of job {}; generating the PDF without it", job.getId(), e);
				return result;
			}
		}).defaultIfEmpty(result)).flatMap(result -> {
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			return pdfReportGenerator.generateReport(result, out, includePassed)
				.then(Mono.fromCallable(() -> new ByteArrayResource(out.toByteArray())));
		})
			.map(resource -> ResponseEntity.ok()
				.header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"orthrus-report.pdf\"")
				.contentType(MediaType.APPLICATION_PDF)
				.body((Resource) resource))
			.defaultIfEmpty(ResponseEntity.notFound().<Resource>build());
	}

}

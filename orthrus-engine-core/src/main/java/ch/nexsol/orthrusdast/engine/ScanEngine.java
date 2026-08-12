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

package ch.nexsol.orthrusdast.engine;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import ch.nexsol.orthrusdast.http.ScanHttpClient;
import ch.nexsol.orthrusdast.ingestion.EndpointDiscoverer;
import ch.nexsol.orthrusdast.model.AttemptStatus;
import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.ScanAttempt;
import ch.nexsol.orthrusdast.model.ScanConfiguration;
import ch.nexsol.orthrusdast.model.Vulnerability;
import ch.nexsol.orthrusdast.scanner.ScanContext;
import ch.nexsol.orthrusdast.scanner.ScannerScope;
import ch.nexsol.orthrusdast.scanner.SecurityScanner;

/**
 * Core engine that orchestrates the scanning process reactively.
 */
@Service
public class ScanEngine {

	private static final Logger log = LoggerFactory.getLogger(ScanEngine.class);

	private final List<SecurityScanner> allScanners;

	private final ScanHttpClient httpClient;

	public ScanEngine(List<SecurityScanner> scanners, ScanHttpClient httpClient) {
		this.allScanners = scanners;
		this.httpClient = httpClient;
	}

	public List<SecurityScanner> getAllScanners() {
		return allScanners;
	}

	/**
	 * Discovers operations without running scanners.
	 * @param discoverer the discoverer
	 * @param targetUrl the targetUrl
	 * @param config the config
	 * @return a Mono of discovered operations
	 */
	public Mono<List<Operation>> runDiscovery(EndpointDiscoverer discoverer, String targetUrl,
			ScanConfiguration config) {
		log.info("Starting discovery on target: {}", targetUrl);
		return discoverer.discover(targetUrl, config);
	}

	public Flux<ScanAttempt> runScan(EndpointDiscoverer discoverer, String targetUrl, ScanConfiguration config) {
		log.info("Starting scan engine with concurrency: {}", config.concurrency());

		// Filter scanners based on configuration
		List<SecurityScanner> activeScanners = allScanners.stream()
			.filter((s) -> config.shouldRunScanner(s.getId()))
			.toList();

		log.info("Active scanners: {}", activeScanners.stream().map(SecurityScanner::getId).toList());

		return discoverer.discover(targetUrl, config).flatMapMany((operations) -> {
			if (operations.isEmpty()) {
				log.error("No operations discovered. Scan cannot proceed.");
				return Flux.error(new IllegalStateException(
						"Discovery failed or no endpoints found. Please check your target URL and documentation."));
			}

			log.info("Discovered {} operations. Starting scan...", operations.size());
			return scanAll(operations, activeScanners, config);
		});
	}

	/**
	 * Runs specific family of scanners on pre-discovered operations.
	 * @param operations the operations
	 * @param family the scanner family to run
	 * @param config the configuration
	 * @return the flux of scan attempts
	 */
	public Flux<ScanAttempt> runScannersOnOperations(List<Operation> operations,
			ch.nexsol.orthrusdast.scanner.ScannerFamily family, ScanConfiguration config) {
		log.info("Starting scan engine for family: {} with concurrency: {}", family, config.concurrency());

		List<SecurityScanner> activeScanners = allScanners.stream()
			.filter((s) -> s.getFamily() == family)
			.filter((s) -> config.shouldRunScanner(s.getId()))
			.toList();

		log.info("Active scanners for family {}: {}", family,
				activeScanners.stream().map(SecurityScanner::getId).toList());

		return scanAll(operations, activeScanners, config);
	}

	private Flux<ScanAttempt> scanAll(List<Operation> operations, List<SecurityScanner> scanners,
			ScanConfiguration config) {
		List<SecurityScanner> operationScanners = scanners.stream()
			.filter((s) -> s.getScope() != ScannerScope.HOST)
			.toList();
		List<SecurityScanner> hostScanners = scanners.stream()
			.filter((s) -> s.getScope() == ScannerScope.HOST)
			.toList();

		Flux<ScanAttempt> perOperation = Flux.fromIterable(operations)
			.flatMap((op) -> scanOperation(op, operationScanners, config), config.concurrency());

		Flux<ScanAttempt> perHost = Flux.empty();
		if (!hostScanners.isEmpty()) {
			// One representative operation per host: host-scoped scanners (TLS, scheme
			// enforcement) probe a property that is identical across every endpoint on
			// the
			// same host, so running them once avoids dozens of duplicate probes.
			Map<String, Operation> representativeByHost = new LinkedHashMap<>();
			for (Operation op : operations) {
				representativeByHost.putIfAbsent(hostKey(op), op);
			}
			log.info("Running {} host-scoped scanner(s) once per host across {} host(s)", hostScanners.size(),
					representativeByHost.size());
			perHost = Flux.fromIterable(representativeByHost.values())
				.flatMap((op) -> scanHost(op, hostScanners, config), config.concurrency());
		}

		return Flux.merge(perOperation, perHost).doOnNext((attempt) -> {
			for (Vulnerability vuln : attempt.vulnerabilities()) {
				log.warn("Found vulnerability: {} [{}] on {}", vuln.name(), vuln.riskLevel(), vuln.operationUrl());
			}
		});
	}

	private Flux<ScanAttempt> scanOperation(Operation operation, List<SecurityScanner> scanners,
			ScanConfiguration config) {
		if (scanners.isEmpty()) {
			return Flux.empty();
		}
		log.debug("Scanning operation: {} {}", operation.method().name(), operation.url());
		// A single baseline request per operation, shared with scanners via ScanContext
		// so
		// they do not each re-issue the same unmodified request.
		return httpClient.send(operation).flatMapMany((response) -> {
			if (response.statusCode().value() == 401 || response.statusCode().value() == 403) {
				log.warn("Operation {} {} returned auth error {}. Skipping scanners.", operation.method().name(),
						operation.url(), response.statusCode().value());
				return Flux.fromIterable(scanners)
					.map((scanner) -> new ScanAttempt(scanner.getId(), scanner.getName(), operation.method().name(),
							operation.url(), AttemptStatus.AUTH_ERROR, List.of()));
			}

			// Only share a genuine response as the baseline. A 5xx (including the
			// synthetic
			// 503 produced when the baseline request failed) is unreliable as a timing or
			// body baseline — sharing it would, for instance, feed a 60s synthetic
			// latency
			// into time-based injection detection — so scanners fall back to their own
			// probe.
			ScanContext context = (response.statusCode().value() >= 500) ? new ScanContext(null)
					: new ScanContext(response);
			return Flux.fromIterable(scanners).flatMap((scanner) -> runScanner(scanner, operation, config, context));
		}).onErrorResume((e) -> {
			log.error("Baseline request failed for operation {}: {}", operation.url(), e.getMessage());
			return Flux.fromIterable(scanners)
				.map((scanner) -> new ScanAttempt(scanner.getId(), scanner.getName(), operation.method().name(),
						operation.url(), AttemptStatus.ERROR, List.of()));
		});
	}

	private Flux<ScanAttempt> scanHost(Operation representative, List<SecurityScanner> scanners,
			ScanConfiguration config) {
		log.debug("Scanning host: {}", hostKey(representative));
		// Host-scoped scanners do their own probing (TLS handshake, scheme downgrade) and
		// do not need the engine baseline, so no baseline request is issued here.
		ScanContext context = new ScanContext(null);
		return Flux.fromIterable(scanners).flatMap((scanner) -> runScanner(scanner, representative, config, context));
	}

	private Mono<ScanAttempt> runScanner(SecurityScanner scanner, Operation operation, ScanConfiguration config,
			ScanContext context) {
		return scanner.scan(operation, config, context)
			.collectList()
			.map((vulns) -> new ScanAttempt(scanner.getId(), scanner.getName(), operation.method().name(),
					operation.url(), vulns.isEmpty() ? AttemptStatus.PASSED : AttemptStatus.FAILED, vulns))
			.onErrorResume((e) -> {
				log.error("Scanner {} failed on operation {}: {}", scanner.getId(), operation.url(), e.getMessage());
				return Mono.just(new ScanAttempt(scanner.getId(), scanner.getName(), operation.method().name(),
						operation.url(), AttemptStatus.ERROR, List.of()));
			});
	}

	private static String hostKey(Operation operation) {
		try {
			URI uri = URI.create(operation.url());
			String scheme = (uri.getScheme() != null) ? uri.getScheme().toLowerCase() : "";
			String host = (uri.getHost() != null) ? uri.getHost().toLowerCase() : "";
			// Normalize the implicit default port so e.g. https://h/a and https://h:443/b
			// collapse to the same host and host-scoped scanners run only once.
			int port = uri.getPort();
			if (port == -1) {
				port = switch (scheme) {
					case "https" -> 443;
					case "http" -> 80;
					default -> -1;
				};
			}
			return scheme + "://" + host + ":" + port;
		}
		catch (RuntimeException ex) {
			return String.valueOf(operation.url());
		}
	}

}

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

package ch.nexsol.orthrusdast.api;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.Disposable;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import tools.jackson.databind.ObjectMapper;

import ch.nexsol.orthrusdast.client.MasterApiClient;
import ch.nexsol.orthrusdast.engine.ScanService;
import ch.nexsol.orthrusdast.model.NodeStatus;
import ch.nexsol.orthrusdast.model.ScanAttempt;
import ch.nexsol.orthrusdast.model.ScanConfiguration;

@RestController
@RequestMapping("/api/v1/slave")
@ConditionalOnProperty(name = "orthrus.slave.mode", havingValue = "server", matchIfMissing = true)
public class SlaveApiController {

	private final ScanService scanService;

	private final MasterApiClient masterApiClient;

	private final ObjectMapper objectMapper;

	private final Map<Long, Disposable> activeJobs = new ConcurrentHashMap<>();

	public SlaveApiController(ScanService scanService, MasterApiClient masterApiClient, ObjectMapper objectMapper) {
		this.scanService = scanService;
		this.masterApiClient = masterApiClient;
		this.objectMapper = objectMapper;
	}

	@PostMapping("/scans")
	public Mono<ResponseEntity<Void>> receiveScanJob(@RequestBody ScanJobRequest request) {
		// Mark as BUSY
		masterApiClient.setStatus(NodeStatus.BUSY);

		return Mono.fromCallable(() -> objectMapper.readValue(request.scanConfigurationJson(), ScanConfiguration.class))
			.flatMap((config) -> {
				Instant startTime = Instant.now();
				AtomicInteger testsCount = new AtomicInteger();
				AtomicInteger vulnsCount = new AtomicInteger();

				Disposable disposable = scanService.executeScan(request.discovererId(), request.target(), config)
					.bufferTimeout(10, Duration.ofSeconds(1))
					.flatMap((batch) -> {
						testsCount.addAndGet(batch.size());
						for (ScanAttempt attempt : batch) {
							if (attempt.vulnerabilities() != null) {
								vulnsCount.addAndGet(attempt.vulnerabilities().size());
							}
						}
						return masterApiClient.sendJobAttemptsBatch(request.jobId(), batch);
					})
					.then(Mono.defer(() -> {
						LoggerFactory.getLogger(SlaveApiController.class)
							.info("Scan job {} completed. {} tests executed, {} vulnerabilities found.",
									request.jobId(), testsCount.get(), vulnsCount.get());
						return masterApiClient.completeJob(request.jobId(), startTime);
					}))
					.doOnError((e) -> {
						LoggerFactory.getLogger(SlaveApiController.class).error("Error executing scan job", e);
						masterApiClient.failJob(request.jobId(), "Slave encountered an error: " + e.getMessage())
							.subscribe();
					})
					.doFinally((signalType) -> activeJobs.remove(request.jobId()))
					.subscribeOn(Schedulers.boundedElastic())
					.subscribe();

				activeJobs.put(request.jobId(), disposable);

				return Mono.just(ResponseEntity.accepted().<Void>build());
			})
			.onErrorResume((e) -> {
				masterApiClient.setStatus(NodeStatus.IDLE);
				return Mono.just(ResponseEntity.badRequest().<Void>build());
			});
	}

	@PostMapping("/tasks")
	public Mono<ResponseEntity<Void>> receiveScanTask(@RequestBody ScanTaskRequest request) {
		masterApiClient.setStatus(NodeStatus.BUSY);

		return Mono.fromCallable(() -> objectMapper.readValue(request.scanConfigurationJson(), ScanConfiguration.class))
			.flatMap((config) -> {
				Instant startTime = Instant.now();

				ch.nexsol.orthrusdast.scanner.ScannerFamily family = ch.nexsol.orthrusdast.scanner.ScannerFamily
					.valueOf(request.phase());
				AtomicInteger testsCount = new AtomicInteger();
				AtomicInteger vulnsCount = new AtomicInteger();

				Disposable disposable = scanService.executeDiscovery(request.discovererId(), request.target(), config)
					.flatMapMany((parsedEndpoints) -> scanService.executeScanFamily(parsedEndpoints, family, config))
					.bufferTimeout(10, Duration.ofSeconds(1))
					.flatMap((batch) -> {
						testsCount.addAndGet(batch.size());
						for (ScanAttempt attempt : batch) {
							if (attempt.vulnerabilities() != null) {
								vulnsCount.addAndGet(attempt.vulnerabilities().size());
							}
						}
						return masterApiClient.sendTaskAttemptsBatch(request.taskId(), batch);
					})
					.then(Mono.defer(() -> {
						LoggerFactory.getLogger(SlaveApiController.class)
							.info("Scan task {} completed. {} tests executed, {} vulnerabilities found.",
									request.taskId(), testsCount.get(), vulnsCount.get());
						return masterApiClient.completeTask(request.taskId(), startTime, testsCount.get(),
								vulnsCount.get());
					}))
					.doOnError((e) -> {
						LoggerFactory.getLogger(SlaveApiController.class).error("Error executing scan task", e);
						masterApiClient.failTask(request.taskId(), "Slave encountered an error: " + e.getMessage())
							.subscribe();
					})
					.doFinally((signalType) -> activeJobs.remove(request.taskId()))
					.subscribeOn(Schedulers.boundedElastic())
					.subscribe();

				activeJobs.put(request.taskId(), disposable);

				return Mono.just(ResponseEntity.accepted().<Void>build());
			})
			.onErrorResume((e) -> {
				masterApiClient.setStatus(NodeStatus.IDLE);
				return Mono.just(ResponseEntity.badRequest().<Void>build());
			});
	}

	@DeleteMapping("/scans/{id}")
	public Mono<ResponseEntity<Void>> cancelScanJob(@PathVariable Long id) {
		Disposable disposable = activeJobs.remove(id);
		if (disposable != null && !disposable.isDisposed()) {
			disposable.dispose();
			masterApiClient.setStatus(NodeStatus.IDLE);
			return Mono.just(ResponseEntity.ok().<Void>build());
		}
		return Mono.just(ResponseEntity.notFound().build());
	}

	@GetMapping("/capabilities")
	public Mono<ResponseEntity<CapabilitiesResponse>> getCapabilities() {
		List<ScannerInfo> scanners = scanService.getAvailableScannerObjects()
			.stream()
			.map((s) -> new ScannerInfo(s.getId(), s.getName()))
			.toList();
		return Mono.just(ResponseEntity.ok(new CapabilitiesResponse(scanService.getAvailableDiscoverers(), scanners)));
	}

	public record CapabilitiesResponse(List<String> discoverers, List<ScannerInfo> scanners) {
	}

	public record ScannerInfo(String id, String name) {
	}

	public record ScanJobRequest(Long jobId, String discovererId, String target, String scanConfigurationJson) {
	}

	public record ScanTaskRequest(Long taskId, Long jobId, String phase, String discovererId, String target,
			String scanConfigurationJson) {
	}

}

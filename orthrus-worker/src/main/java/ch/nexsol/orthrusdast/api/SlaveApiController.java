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
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.event.ContextClosedEvent;
import org.springframework.context.event.EventListener;
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
import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.ScanAttempt;
import ch.nexsol.orthrusdast.model.ScanConfiguration;
import ch.nexsol.orthrusdast.scanner.ScannerFamily;

@RestController
@RequestMapping("/api/v1/slave")
@ConditionalOnProperty(name = "orthrus.slave.mode", havingValue = "server", matchIfMissing = true)
public class SlaveApiController {

	private static final Logger log = LoggerFactory.getLogger(SlaveApiController.class);

	private static final Duration DISCOVERY_CACHE_TTL = Duration.ofMinutes(30);

	private static final int MAX_CACHED_DISCOVERIES = 8;

	private final ScanService scanService;

	private final MasterApiClient masterApiClient;

	private final ObjectMapper objectMapper;

	private final Map<Long, Disposable> activeTasks = new ConcurrentHashMap<>();

	/**
	 * Discovery result shared by every family task of the same job, so a target is
	 * crawled once per job rather than once per scanner family. Bounded by age and by
	 * count, since a job's tasks do not necessarily overlap in time.
	 */
	private final Map<Long, Mono<List<Operation>>> discoveryByJob = Collections
		.synchronizedMap(new LinkedHashMap<Long, Mono<List<Operation>>>(16, 0.75f, true) {
			@Override
			protected boolean removeEldestEntry(Map.Entry<Long, Mono<List<Operation>>> eldest) {
				return size() > MAX_CACHED_DISCOVERIES;
			}
		});

	public SlaveApiController(ScanService scanService, MasterApiClient masterApiClient, ObjectMapper objectMapper) {
		this.scanService = scanService;
		this.masterApiClient = masterApiClient;
		this.objectMapper = objectMapper;
	}

	@EventListener(ContextClosedEvent.class)
	public void onShutdown() {
		log.info("Graceful shutdown initiated. Cancelling {} active task(s)...", activeTasks.size());
		masterApiClient.markOffline();
		for (Map.Entry<Long, Disposable> entry : activeTasks.entrySet()) {
			Disposable disposable = entry.getValue();
			if (!disposable.isDisposed()) {
				disposable.dispose();
				masterApiClient.failTask(entry.getKey(), "Worker is shutting down gracefully").subscribe();
			}
		}
		activeTasks.clear();
		discoveryByJob.clear();
	}

	@PostMapping("/tasks")
	public Mono<ResponseEntity<Void>> receiveScanTask(@RequestBody ScanTaskRequest request) {
		return Mono.fromCallable(() -> objectMapper.readValue(request.scanConfigurationJson(), ScanConfiguration.class))
			.flatMap((config) -> {
				Instant startTime = Instant.now();
				ScannerFamily family = ScannerFamily.valueOf(request.phase());
				AtomicInteger testsCount = new AtomicInteger();
				AtomicInteger vulnsCount = new AtomicInteger();

				Disposable disposable = discoverOnce(request, config)
					.flatMapMany((endpoints) -> scanService.executeScanFamily(endpoints, family, config))
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
						log.info("Scan task {} ({}) completed. {} tests executed, {} vulnerabilities found.",
								request.taskId(), request.phase(), testsCount.get(), vulnsCount.get());
						return masterApiClient.completeTask(request.taskId(), startTime, testsCount.get(),
								vulnsCount.get());
					}))
					.doOnError((e) -> {
						log.error("Error executing scan task {}", request.taskId(), e);
						masterApiClient.failTask(request.taskId(), "Slave encountered an error: " + e.getMessage())
							.subscribe();
					})
					.doFinally((signalType) -> taskFinished(request.taskId()))
					.subscribeOn(Schedulers.boundedElastic())
					.subscribe();

				activeTasks.put(request.taskId(), disposable);
				masterApiClient.reportLoad(activeTasks.size());

				return Mono.just(ResponseEntity.accepted().<Void>build());
			})
			.onErrorResume((e) -> {
				log.error("Rejecting scan task {}: {}", request.taskId(), e.getMessage());
				return Mono.just(ResponseEntity.badRequest().<Void>build());
			});
	}

	/**
	 * Runs discovery for the task's job, or joins the one already in flight for it.
	 * @param request the incoming task
	 * @param config the scan configuration carried by the task
	 * @return the operations discovered for the job's target
	 */
	private Mono<List<Operation>> discoverOnce(ScanTaskRequest request, ScanConfiguration config) {
		return this.discoveryByJob.computeIfAbsent(request.jobId(),
				(jobId) -> this.scanService.executeDiscovery(request.discovererId(), request.target(), config)
					.doOnSubscribe(
							(s) -> log.info("Running discovery for job {} on target {}", jobId, request.target()))
					.cache(DISCOVERY_CACHE_TTL));
	}

	private void taskFinished(Long taskId) {
		this.activeTasks.remove(taskId);
		this.masterApiClient.reportLoad(this.activeTasks.size());
	}

	@DeleteMapping("/tasks/{id}")
	public Mono<ResponseEntity<Void>> cancelScanTask(@PathVariable Long id) {
		Disposable disposable = this.activeTasks.remove(id);
		if (disposable == null || disposable.isDisposed()) {
			return Mono.just(ResponseEntity.notFound().build());
		}
		log.info("Cancelling task {} on operator request", id);
		disposable.dispose();
		this.masterApiClient.reportLoad(this.activeTasks.size());
		return Mono.just(ResponseEntity.ok().<Void>build());
	}

	@GetMapping("/capabilities")
	public Mono<ResponseEntity<CapabilitiesResponse>> getCapabilities() {
		List<ScannerInfo> scanners = this.scanService.getAvailableScannerObjects()
			.stream()
			.map((s) -> new ScannerInfo(s.getId(), s.getName()))
			.toList();
		return Mono
			.just(ResponseEntity.ok(new CapabilitiesResponse(this.scanService.getAvailableDiscoverers(), scanners)));
	}

	public record CapabilitiesResponse(List<String> discoverers, List<ScannerInfo> scanners) {
	}

	public record ScannerInfo(String id, String name) {
	}

	public record ScanTaskRequest(Long taskId, Long jobId, String phase, String discovererId, String target,
			String scanConfigurationJson) {
	}

}

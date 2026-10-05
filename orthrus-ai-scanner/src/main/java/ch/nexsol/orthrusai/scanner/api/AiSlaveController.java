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

package ch.nexsol.orthrusai.scanner.api;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

import ch.nexsol.orthrus.protocol.node.ScanAttempt;
import ch.nexsol.orthrus.protocol.node.ScanTaskRequest;
import ch.nexsol.orthrusai.scanner.client.ManagerClient;
import ch.nexsol.orthrusai.scanner.config.AiScannerProperties;
import ch.nexsol.orthrusai.scanner.scan.ScanExecutor;

/**
 * Exposes the same worker&lt;-&gt;manager surface a regular worker does, so the manager
 * dispatches tasks here without knowing the work is done by an LLM. Accepts a task,
 * acknowledges immediately, runs it asynchronously, and streams attempts back before
 * completing (or failing) the task.
 */
@RestController
@RequestMapping("/api/v1/slave")
public class AiSlaveController {

	private static final Logger log = LoggerFactory.getLogger(AiSlaveController.class);

	private final ScanExecutor scanExecutor;

	private final ManagerClient managerClient;

	private final long taskTimeoutSeconds;

	private final Map<Long, Disposable> activeTasks = new ConcurrentHashMap<>();

	public AiSlaveController(ScanExecutor scanExecutor, ManagerClient managerClient, AiScannerProperties properties) {
		this.scanExecutor = scanExecutor;
		this.managerClient = managerClient;
		this.taskTimeoutSeconds = properties.getAi().getBudget().getTaskTimeoutSeconds();
	}

	@EventListener(ContextClosedEvent.class)
	public void onShutdown() {
		log.info("Shutdown: cancelling {} active task(s)", this.activeTasks.size());
		this.managerClient.markOffline();
		for (Map.Entry<Long, Disposable> entry : this.activeTasks.entrySet()) {
			Disposable disposable = entry.getValue();
			if (!disposable.isDisposed()) {
				disposable.dispose();
				this.managerClient.failTask(entry.getKey(), "AI scanner is shutting down").subscribe();
			}
		}
		this.activeTasks.clear();
	}

	@PostMapping("/tasks")
	public Mono<ResponseEntity<Void>> receiveScanTask(@RequestBody ScanTaskRequest request) {
		Instant startTime = Instant.now();
		AtomicInteger testsCount = new AtomicInteger();
		AtomicInteger vulnsCount = new AtomicInteger();

		Instant deadline = startTime.plusSeconds(this.taskTimeoutSeconds);

		Disposable disposable = this.scanExecutor.execute(request)
			// Flux.timeout(Duration) only bounds the gap between two attempts; the budget
			// covers the whole task, so every timeout window ends at the same deadline.
			.timeout(untilDeadline(deadline), (attempt) -> untilDeadline(deadline))
			.onErrorMap(TimeoutException.class,
					(e) -> new TimeoutException("task timed out after " + this.taskTimeoutSeconds + " s"))
			.bufferTimeout(10, Duration.ofSeconds(1))
			.flatMap((batch) -> {
				testsCount.addAndGet(batch.size());
				for (ScanAttempt attempt : batch) {
					if (attempt.vulnerabilities() != null) {
						vulnsCount.addAndGet(attempt.vulnerabilities().size());
					}
				}
				return this.managerClient.sendTaskAttemptsBatch(request.taskId(), batch);
			})
			.then(Mono.defer(() -> {
				log.info("Task {} ({}) completed: {} tests, {} vulnerabilities", request.taskId(), request.phase(),
						testsCount.get(), vulnsCount.get());
				return this.managerClient.completeTask(request.taskId(), startTime, testsCount.get(), vulnsCount.get());
			}))
			.doOnError((e) -> {
				log.error("Task {} failed", request.taskId(), e);
				this.managerClient.failTask(request.taskId(), "AI scanner error: " + e.getMessage()).subscribe();
			})
			.doFinally((signal) -> taskFinished(request.taskId()))
			.subscribeOn(Schedulers.boundedElastic())
			.subscribe();

		this.activeTasks.put(request.taskId(), disposable);
		this.managerClient.reportLoad(this.activeTasks.size());
		return Mono.just(ResponseEntity.accepted().build());
	}

	@DeleteMapping("/tasks/{id}")
	public Mono<ResponseEntity<Void>> cancelScanTask(@PathVariable Long id) {
		Disposable disposable = this.activeTasks.remove(id);
		if (disposable == null || disposable.isDisposed()) {
			return Mono.just(ResponseEntity.notFound().build());
		}
		log.info("Cancelling task {} on operator request", id);
		disposable.dispose();
		this.managerClient.reportLoad(this.activeTasks.size());
		return Mono.just(ResponseEntity.ok().build());
	}

	@GetMapping("/capabilities")
	public Mono<ResponseEntity<CapabilitiesResponse>> getCapabilities() {
		return Mono.just(ResponseEntity.ok(new CapabilitiesResponse(List.of(), List.of())));
	}

	/**
	 * A signal firing at the deadline, computed on subscription so each timeout window
	 * only covers what is left of the task budget.
	 * @param deadline when the task budget runs out
	 * @return a signal emitting once the deadline is reached
	 */
	private static Mono<Long> untilDeadline(Instant deadline) {
		return Mono.defer(() -> {
			Duration remaining = Duration.between(Instant.now(), deadline);
			return Mono.delay(remaining.isNegative() ? Duration.ZERO : remaining);
		});
	}

	private void taskFinished(Long taskId) {
		this.activeTasks.remove(taskId);
		this.managerClient.reportLoad(this.activeTasks.size());
	}

	/**
	 * Shape the manager's health ping expects from {@code GET /capabilities}.
	 *
	 * @param discoverers discoverer ids (unused by the AI node's self-recon)
	 * @param scanners scanner descriptors
	 */
	public record CapabilitiesResponse(List<String> discoverers, List<ScannerInfo> scanners) {
	}

	/**
	 * A scanner descriptor.
	 *
	 * @param id scanner id
	 * @param name scanner name
	 */
	public record ScannerInfo(String id, String name) {
	}

}

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

package ch.nexsol.orthrusdast.sse;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.context.event.ContextClosedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Sinks;

/**
 * Manages Server-Sent Event sinks keyed by scan job ID. Browsers subscribe to a Flux for
 * a given job and receive updates when the job status changes (PENDING → RUNNING →
 * COMPLETED/FAILED).
 */
@Component
public class JobEventPublisher {

	private final Map<Long, Sinks.Many<JobEvent>> sinks = new ConcurrentHashMap<>();

	private final Sinks.Many<JobEvent> globalSink = Sinks.many().replay().limit(50);

	/**
	 * Get or create a Flux for a given job ID.
	 * @param jobId the job ID
	 * @return a flux of job events
	 */
	public Flux<JobEvent> stream(Long jobId) {
		return getOrCreateSink(jobId).asFlux();
	}

	/**
	 * Subscribe to all events globally.
	 * @return a flux of job events globally
	 */
	public Flux<JobEvent> globalStream() {
		return globalSink.asFlux();
	}

	/**
	 * Emit an event to all subscribers of a given job, and globally.
	 * @param jobId the job ID
	 * @param event the job event to emit
	 */
	public void emit(Long jobId, JobEvent event) {
		getOrCreateSink(jobId).tryEmitNext(event);
		globalSink.tryEmitNext(event);
	}

	/**
	 * Complete the sink for a given job (no more events will be sent). This closes the
	 * EventSource on the client side.
	 * @param jobId the job id
	 */
	public void complete(Long jobId) {
		Sinks.Many<JobEvent> sink = sinks.remove(jobId);
		if (sink != null) {
			sink.tryEmitComplete();
		}
	}

	private Sinks.Many<JobEvent> getOrCreateSink(Long jobId) {
		return sinks.computeIfAbsent(jobId, (id) -> Sinks.many().replay().latest());
	}

	/**
	 * When the application is shutting down (e.g. Ctrl+C), we must close all infinite SSE
	 * streams so that Netty's Graceful Shutdown doesn't wait 30 seconds for them.
	 */
	@EventListener(ContextClosedEvent.class)
	public void onShutdown() {
		globalSink.tryEmitComplete();
		sinks.values().forEach(Sinks.Many::tryEmitComplete);
		sinks.clear();
	}

}

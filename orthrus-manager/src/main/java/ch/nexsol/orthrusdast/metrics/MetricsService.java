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

package ch.nexsol.orthrusdast.metrics;

import java.util.concurrent.atomic.AtomicInteger;

import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import ch.nexsol.orthrusdast.model.JobStatus;
import ch.nexsol.orthrusdast.repository.ScanJobRepository;
import ch.nexsol.orthrusdast.repository.ScanTaskRepository;

@Service
@EnableScheduling
public class MetricsService {

	private final ScanJobRepository scanJobRepository;

	private final ScanTaskRepository scanTaskRepository;

	private final AtomicInteger pendingJobsCounter;

	private final AtomicInteger pendingTasksCounter;

	public MetricsService(MeterRegistry meterRegistry, ScanJobRepository scanJobRepository,
			ScanTaskRepository scanTaskRepository) {
		this.scanJobRepository = scanJobRepository;
		this.scanTaskRepository = scanTaskRepository;
		this.pendingJobsCounter = meterRegistry.gauge("orthrus.jobs.pending", new AtomicInteger(0));
		this.pendingTasksCounter = meterRegistry.gauge("orthrus.tasks.pending", new AtomicInteger(0));
	}

	@Scheduled(fixedDelay = 10000)
	public void updateMetrics() {
		scanJobRepository.countByStatus(JobStatus.PENDING)
			.subscribe((count) -> pendingJobsCounter.set(count.intValue()));
		scanTaskRepository.countByStatus(JobStatus.PENDING)
			.subscribe((count) -> pendingTasksCounter.set(count.intValue()));
	}

}

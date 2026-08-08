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

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import tools.jackson.databind.ObjectMapper;

import ch.nexsol.orthrusdast.client.MasterApiClient;
import ch.nexsol.orthrusdast.engine.ScanService;
import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.ScanConfiguration;
import ch.nexsol.orthrusdast.scanner.ScannerFamily;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SlaveApiControllerTest {

	private static final long JOB_ID = 42L;

	@Mock
	private ScanService scanService;

	@Mock
	private MasterApiClient masterApiClient;

	private final ObjectMapper objectMapper = new ObjectMapper();

	private SlaveApiController controller;

	private final AtomicInteger discoveryRuns = new AtomicInteger();

	@BeforeEach
	void setUp() {
		this.controller = new SlaveApiController(this.scanService, this.masterApiClient, this.objectMapper);

		List<Operation> discovered = List.of(Operation.simple("https://target.example/users", HttpMethod.GET));
		when(this.scanService.executeDiscovery(anyString(), anyString(), any(ScanConfiguration.class)))
			.thenReturn(Mono.fromSupplier(() -> {
				this.discoveryRuns.incrementAndGet();
				return discovered;
			}));
		when(this.scanService.executeScanFamily(any(), any(ScannerFamily.class), any(ScanConfiguration.class)))
			.thenReturn(Flux.empty());
		when(this.masterApiClient.completeTask(anyLong(), any(), anyInt(), anyInt())).thenReturn(Mono.empty());
		when(this.masterApiClient.failTask(anyLong(), anyString())).thenReturn(Mono.empty());
	}

	@Test
	void everyFamilyTaskOfAJobSharesASingleDiscovery() {
		List<ScannerFamily> families = List.of(ScannerFamily.INJECTION, ScannerFamily.XSS, ScannerFamily.AUTHENTICATION,
				ScannerFamily.CONFIGURATION, ScannerFamily.LOGIC, ScannerFamily.MISC);

		long taskId = 1;
		for (ScannerFamily family : families) {
			assertThat(accept(taskId++, JOB_ID, family)).isEqualTo(HttpStatus.ACCEPTED);
		}

		verify(this.masterApiClient, timeout(5000).times(families.size())).completeTask(anyLong(), any(), anyInt(),
				anyInt());

		assertThat(this.discoveryRuns).hasValue(1);
		verify(this.scanService, timeout(5000).times(1)).executeDiscovery(anyString(), anyString(),
				any(ScanConfiguration.class));
		verify(this.scanService, timeout(5000).times(families.size())).executeScanFamily(any(),
				any(ScannerFamily.class), any(ScanConfiguration.class));
	}

	@Test
	void aFamilyThatFinishesBeforeTheNextIsDispatchedStillSharesTheDiscovery() {
		// A family whose scanners were all excluded returns instantly, so the tasks of
		// the
		// job do not overlap in time.
		assertThat(accept(1L, JOB_ID, ScannerFamily.INJECTION)).isEqualTo(HttpStatus.ACCEPTED);
		verify(this.masterApiClient, timeout(5000).times(1)).completeTask(anyLong(), any(), anyInt(), anyInt());

		assertThat(accept(2L, JOB_ID, ScannerFamily.XSS)).isEqualTo(HttpStatus.ACCEPTED);
		verify(this.masterApiClient, timeout(5000).times(2)).completeTask(anyLong(), any(), anyInt(), anyInt());

		assertThat(this.discoveryRuns).hasValue(1);
	}

	@Test
	void tasksOfDifferentJobsEachGetTheirOwnDiscovery() {
		assertThat(accept(1L, JOB_ID, ScannerFamily.INJECTION)).isEqualTo(HttpStatus.ACCEPTED);
		assertThat(accept(2L, JOB_ID + 1, ScannerFamily.INJECTION)).isEqualTo(HttpStatus.ACCEPTED);

		verify(this.masterApiClient, timeout(5000).times(2)).completeTask(anyLong(), any(), anyInt(), anyInt());
		assertThat(this.discoveryRuns).hasValue(2);
	}

	@Test
	void anUnparseableConfigurationIsRejectedRatherThanStartingAScan() {
		SlaveApiController.ScanTaskRequest request = new SlaveApiController.ScanTaskRequest(1L, JOB_ID,
				ScannerFamily.INJECTION.name(), "openapi", "https://target.example", "not json");

		HttpStatus status = HttpStatus
			.valueOf(this.controller.receiveScanTask(request).block().getStatusCode().value());

		assertThat(status).isEqualTo(HttpStatus.BAD_REQUEST);
		assertThat(this.discoveryRuns).hasValue(0);
	}

	@Test
	void cancellingAnUnknownTaskReportsNotFound() {
		HttpStatus status = HttpStatus.valueOf(this.controller.cancelScanTask(999L).block().getStatusCode().value());

		assertThat(status).isEqualTo(HttpStatus.NOT_FOUND);
	}

	private HttpStatus accept(long taskId, long jobId, ScannerFamily family) {
		SlaveApiController.ScanTaskRequest request = new SlaveApiController.ScanTaskRequest(taskId, jobId,
				family.name(), "openapi", "https://target.example",
				this.objectMapper.writeValueAsString(ScanConfiguration.defaults()));
		return HttpStatus.valueOf(this.controller.receiveScanTask(request).block().getStatusCode().value());
	}

}

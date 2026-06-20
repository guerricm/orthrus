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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Pageable;
import org.springframework.ui.ConcurrentModel;
import org.springframework.ui.Model;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Flux;

import ch.nexsol.orthrusdast.engine.ScanResultService;
import ch.nexsol.orthrusdast.repository.ScanJobRepository;
import ch.nexsol.orthrusdast.repository.SlaveNodeRepository;
import ch.nexsol.orthrusdast.repository.TestPlanRepository;
import ch.nexsol.orthrusdast.sse.JobEventPublisher;

import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ScanViewControllerTest {

	@Mock
	private ScanJobRepository scanJobRepository;

	@Mock
	private ScanResultService scanResultService;

	@Mock
	private TestPlanRepository testPlanRepository;

	@Mock
	private SlaveNodeRepository slaveNodeRepository;

	@Mock
	private JobEventPublisher jobEventPublisher;

	private final tools.jackson.databind.ObjectMapper objectMapper = new tools.jackson.databind.ObjectMapper();

	private ScanViewController controller;

	@BeforeEach
	void setUp() {
		controller = new ScanViewController(scanJobRepository, scanResultService, testPlanRepository,
				slaveNodeRepository, jobEventPublisher, objectMapper, WebClient.builder());
	}

	@Test
	void testGetResultsPage() {
		when(scanJobRepository.findAllByOrderByCreatedAtDesc(ArgumentMatchers.any(Pageable.class)))
			.thenReturn(Flux.empty());

		Model model = new ConcurrentModel();
		String viewName = controller.listScans(model).block();
		Assertions.assertEquals("scans/list", viewName);
		Assertions.assertTrue(model.containsAttribute("history"));
	}

}

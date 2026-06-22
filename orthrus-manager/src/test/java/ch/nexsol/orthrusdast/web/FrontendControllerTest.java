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
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.ui.ConcurrentModel;
import org.springframework.ui.Model;
import reactor.core.publisher.Flux;

import ch.nexsol.orthrusdast.engine.ScanResultService;
import ch.nexsol.orthrusdast.engine.StatisticsService;

import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class FrontendControllerTest {

	@Mock
	private ScanResultService scanResultService;

	@Mock
	private StatisticsService statisticsService;

	@Mock
	private ObjectProvider<ReactiveClientRegistrationRepository> clientRegistrations;

	private FrontendController controller;

	@BeforeEach
	void setUp() {
		controller = new FrontendController(scanResultService, statisticsService, clientRegistrations);
	}

	@Test
	void testGetIndexPage() {
		when(scanResultService.findAll()).thenReturn(Flux.empty());

		Model model = new ConcurrentModel();
		String viewName = controller.index(model).block();
		Assertions.assertEquals("home", viewName);
		Assertions.assertTrue(model.containsAttribute("discoverers"));
	}

}

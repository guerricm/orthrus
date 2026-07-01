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

package ch.nexsol.orthrusdast.cli;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import ch.nexsol.orthrusdast.auth.OAuth2TokenFetcher;
import ch.nexsol.orthrusdast.engine.ScanService;
import ch.nexsol.orthrusdast.report.ReportGenerator;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

class ScanCommandTest {

	@Test
	void testCallWithValidParameters() throws Exception {
		ScanService scanService = Mockito.mock(ScanService.class);
		when(scanService.executeScan(anyString(), any(), any())).thenReturn(Flux.empty());

		ReportGenerator mockGenerator = Mockito.mock(ReportGenerator.class);
		when(mockGenerator.getFormat()).thenReturn("json");
		when(mockGenerator.generateReport(any(), any(), ArgumentMatchers.anyBoolean())).thenReturn(Mono.empty());

		OAuth2TokenFetcher mockFetcher = Mockito.mock(OAuth2TokenFetcher.class);

		ScanCommand command = new ScanCommand(scanService, List.of(mockGenerator), mockFetcher);

		command.discovererId = "openapi";
		command.target = "http://localhost:8080/v3/api-docs";
		command.format = "json";

		Integer result = command.call();
		assertThat(result).isEqualTo(0);
	}

}

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

package ch.nexsol.orthrusdast.scanner;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import ch.nexsol.orthrusdast.http.ScanHttpClient;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Against an endpoint that refuses the configured identity (403), only the scanners
 * probing a way around the refusal, or a property of the response itself, still run.
 */
class ForbiddenScannerSelectionTest {

	private final ScanHttpClient httpClient = Mockito.mock(ScanHttpClient.class);

	@Test
	void bypassAndResponseScannersRunWhenForbidden() {
		List<SecurityScanner> scanners = List.of(new BrokenAuthenticationScanner(this.httpClient),
				new JwtNoneAlgorithmScanner(this.httpClient), new JwtBlankSecretScanner(this.httpClient),
				new BflaScanner(this.httpClient), new HttpMethodTamperingScanner(this.httpClient),
				new CorsScanner(this.httpClient), new SecurityHeadersScanner(this.httpClient));

		assertThat(scanners).allSatisfy((scanner) -> assertThat(scanner.runsWhenForbidden()).isTrue());
	}

	@Test
	void scannersExercisingTheEndpointDoNotRunWhenForbidden() {
		List<SecurityScanner> scanners = List.of(new VerboseErrorScanner(this.httpClient),
				new AuthenticationBruteForceScanner(this.httpClient));

		assertThat(scanners).allSatisfy((scanner) -> assertThat(scanner.runsWhenForbidden()).isFalse());
	}

}

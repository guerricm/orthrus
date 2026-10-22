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

package ch.nexsol.orthrusdast.engine;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.IntStream;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import ch.nexsol.orthrus.protocol.node.AttemptStatus;
import ch.nexsol.orthrus.protocol.node.ScanAttempt;
import ch.nexsol.orthrus.protocol.node.Vulnerability;
import ch.nexsol.orthrusdast.http.ScanHttpClient;
import ch.nexsol.orthrusdast.http.ScanHttpResponse;
import ch.nexsol.orthrusdast.ingestion.EndpointDiscoverer;
import ch.nexsol.orthrusdast.model.GatewayType;
import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.ScanConfiguration;
import ch.nexsol.orthrusdast.scanner.ScannerFamily;
import ch.nexsol.orthrusdast.scanner.SecurityScanner;

import static org.assertj.core.api.Assertions.assertThat;

class ScanEngineTest {

	@Test
	void testExecuteScan_LimitsConcurrency() {
		AtomicInteger activeScans = new AtomicInteger(0);
		AtomicInteger maxScans = new AtomicInteger(0);

		SecurityScanner mockScanner = new SecurityScanner() {
			@Override
			public String getId() {
				return "mock";
			}

			@Override
			public String getName() {
				return "Mock Scanner";
			}

			@Override
			public ch.nexsol.orthrusdast.scanner.ScannerFamily getFamily() {
				return ch.nexsol.orthrusdast.scanner.ScannerFamily.MISC;
			}

			@Override
			public Flux<Vulnerability> scan(Operation operation) {
				return scan(operation, null);
			}

			@Override
			public Flux<Vulnerability> scan(Operation operation, ScanConfiguration config) {
				return Mono.delay(Duration.ofMillis(50)).doOnSubscribe((s) -> {
					int current = activeScans.incrementAndGet();
					synchronized (maxScans) {
						if (current > maxScans.get()) {
							maxScans.set(current);
						}
					}
				}).doFinally((signalType) -> activeScans.decrementAndGet()).flatMapMany((l) -> Flux.empty());
			}
		};

		ScanHttpClient mockHttpClient = Mockito.mock(ScanHttpClient.class);
		Mockito.when(mockHttpClient.send(ArgumentMatchers.any()))
			.thenReturn(Mono.just(new ScanHttpResponse(HttpStatus.OK, new HttpHeaders(), "", 0L)));

		ScanEngine engine = new ScanEngine(List.of(mockScanner), mockHttpClient);

		// Create 20 operations
		Operation op = new Operation("http://localhost", HttpMethod.GET, Map.of(), Map.of(), null, List.of(), List.of(),
				null, null, null);
		List<Operation> operations = IntStream.range(0, 20).mapToObj((i) -> op).toList();

		// Concurrency set to 5
		ScanConfiguration config = new ScanConfiguration(List.of(), List.of(), 5, 5000, 10000, false, "json", null,
				null, "en", false, GatewayType.AUTO, null, null, null, null, null);

		EndpointDiscoverer mockDiscoverer = new EndpointDiscoverer() {
			@Override
			public String getId() {
				return "mock-disc";
			}

			@Override
			public Mono<List<Operation>> discover(String target, ScanConfiguration cfg) {
				return Mono.just(operations);
			}
		};

		List<ScanAttempt> attempts = engine.runScan(mockDiscoverer, "http://localhost", config).collectList().block();

		assertThat(attempts).isNotNull();
		assertThat(attempts).hasSize(20);

		// Assert max concurrency is bounded close to configured value
		assertThat(maxScans.get()).isBetween(5, 6);
	}

	@Test
	void aBaselineRejectingTheCredentialsMarksEveryScannerAsAuthError() {
		AtomicInteger runs = new AtomicInteger();

		StepVerifier.create(scanWithBaseline(HttpStatus.UNAUTHORIZED, false, runs))
			.assertNext((attempt) -> assertThat(attempt.status()).isEqualTo(AttemptStatus.AUTH_ERROR))
			.verifyComplete();
		assertThat(runs).hasValue(0);
	}

	@Test
	void aBaselineRefusingThePermissionMarksAScannerNeedingAccessAsForbidden() {
		AtomicInteger runs = new AtomicInteger();

		StepVerifier.create(scanWithBaseline(HttpStatus.FORBIDDEN, false, runs))
			.assertNext((attempt) -> assertThat(attempt.status()).isEqualTo(AttemptStatus.FORBIDDEN))
			.verifyComplete();
		assertThat(runs).hasValue(0);
	}

	@Test
	void aBaselineAnsweringRunsTheScanners() {
		AtomicInteger runs = new AtomicInteger();

		StepVerifier.create(scanWithBaseline(HttpStatus.NOT_FOUND, false, runs))
			.assertNext((attempt) -> assertThat(attempt.status()).isEqualTo(AttemptStatus.PASSED))
			.verifyComplete();
		assertThat(runs).hasValue(1);
	}

	@Test
	void aBaselineRefusingThePermissionStillRunsTheBypassScanners() {
		AtomicInteger runs = new AtomicInteger();

		StepVerifier.create(scanWithBaseline(HttpStatus.FORBIDDEN, true, runs))
			.assertNext((attempt) -> assertThat(attempt.status()).isEqualTo(AttemptStatus.PASSED))
			.verifyComplete();
		assertThat(runs).hasValue(1);
	}

	@Test
	void aBaselineRejectingTheCredentialsSkipsEvenTheBypassScanners() {
		AtomicInteger runs = new AtomicInteger();

		StepVerifier.create(scanWithBaseline(HttpStatus.UNAUTHORIZED, true, runs))
			.assertNext((attempt) -> assertThat(attempt.status()).isEqualTo(AttemptStatus.AUTH_ERROR))
			.verifyComplete();
		assertThat(runs).hasValue(0);
	}

	private static Flux<ScanAttempt> scanWithBaseline(HttpStatus baseline, boolean runsWhenForbidden,
			AtomicInteger runs) {
		SecurityScanner scanner = new SecurityScanner() {
			@Override
			public String getId() {
				return "counting";
			}

			@Override
			public String getName() {
				return "Counting Scanner";
			}

			@Override
			public ScannerFamily getFamily() {
				return ScannerFamily.MISC;
			}

			@Override
			public boolean runsWhenForbidden() {
				return runsWhenForbidden;
			}

			@Override
			public Flux<Vulnerability> scan(Operation operation) {
				return Flux.defer(() -> {
					runs.incrementAndGet();
					return Flux.empty();
				});
			}
		};
		ScanHttpClient httpClient = Mockito.mock(ScanHttpClient.class);
		Mockito.when(httpClient.send(ArgumentMatchers.any()))
			.thenReturn(Mono.just(new ScanHttpResponse(baseline, new HttpHeaders(), "", 0L)));
		Operation op = new Operation("http://localhost/rooms/1", HttpMethod.GET, Map.of(), Map.of(), null, List.of(),
				List.of(), null, null, null);
		ScanConfiguration config = new ScanConfiguration(List.of(), List.of(), 1, 5000, 10000, false, "json", null,
				null, "en", false, GatewayType.AUTO, null, null, null, null, null);
		return new ScanEngine(List.of(scanner), httpClient).runScannersOnOperations(List.of(op), ScannerFamily.MISC,
				config);
	}

}

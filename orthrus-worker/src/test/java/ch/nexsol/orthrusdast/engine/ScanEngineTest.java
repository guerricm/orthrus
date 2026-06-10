package ch.nexsol.orthrusdast.engine;

import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.ScanConfiguration;
import ch.nexsol.orthrusdast.model.ScanResult;
import ch.nexsol.orthrusdast.model.GatewayType;
import ch.nexsol.orthrusdast.scanner.SecurityScanner;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Flux;

import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ch.nexsol.orthrusdast.http.ScanHttpClient;
import ch.nexsol.orthrusdast.http.ScanHttpResponse;
import ch.nexsol.orthrusdast.ingestion.EndpointDiscoverer;
import ch.nexsol.orthrusdast.model.ScanAttempt;
import ch.nexsol.orthrusdast.model.Vulnerability;
import java.time.Duration;
import java.util.stream.IntStream;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import reactor.core.publisher.Mono;

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
			public Flux<Vulnerability> scan(Operation operation) {
				return scan(operation, null);
			}

			@Override
			public Flux<Vulnerability> scan(Operation operation, ScanConfiguration config) {
				return Mono.delay(Duration.ofMillis(50)).doOnSubscribe(s -> {
					int current = activeScans.incrementAndGet();
					synchronized (maxScans) {
						if (current > maxScans.get()) {
							maxScans.set(current);
						}
					}
				}).doFinally(signalType -> activeScans.decrementAndGet()).flatMapMany(l -> Flux.empty());
			}
		};

		ScanHttpClient mockHttpClient = Mockito.mock(ScanHttpClient.class);
		Mockito.when(mockHttpClient.send(ArgumentMatchers.any()))
			.thenReturn(Mono.just(new ScanHttpResponse(HttpStatus.OK, new HttpHeaders(), "", 0L)));

		ScanEngine engine = new ScanEngine(List.of(mockScanner), mockHttpClient);

		// Create 20 operations
		Operation op = new Operation("http://localhost", HttpMethod.GET, Map.of(), Map.of(), null, List.of(), List.of(),
				null, null, null);
		List<Operation> operations = IntStream.range(0, 20).mapToObj(i -> op).toList();

		// Concurrency set to 5
		ScanConfiguration config = new ScanConfiguration(List.of(), List.of(), 5, 5000, 10000, false, "json", null,
				null, "en", false, GatewayType.AUTO, null, null, null, null);

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

		assertNotNull(attempts);
		assertEquals(20, attempts.size());

		// Assert max concurrency is bounded close to configured value
		assertTrue(maxScans.get() >= 5 && maxScans.get() <= 6,
				"Expected max concurrency around 5, but was " + maxScans.get());
	}

}

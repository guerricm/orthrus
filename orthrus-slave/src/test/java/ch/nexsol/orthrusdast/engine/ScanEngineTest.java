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
            public Flux<ch.nexsol.orthrusdast.model.Vulnerability> scan(Operation operation) {
                return scan(operation, null);
            }

            @Override
            public Flux<ch.nexsol.orthrusdast.model.Vulnerability> scan(Operation operation, ScanConfiguration config) {
                return reactor.core.publisher.Mono.delay(java.time.Duration.ofMillis(50))
                        .doOnSubscribe(s -> {
                            int current = activeScans.incrementAndGet();
                            synchronized (maxScans) {
                                if (current > maxScans.get()) {
                                    maxScans.set(current);
                                }
                            }
                        })
                        .doFinally(signalType -> activeScans.decrementAndGet())
                        .flatMapMany(l -> Flux.empty());
            }
        };

        ch.nexsol.orthrusdast.http.ScanHttpClient mockHttpClient = org.mockito.Mockito.mock(ch.nexsol.orthrusdast.http.ScanHttpClient.class);
        org.mockito.Mockito.when(mockHttpClient.send(org.mockito.ArgumentMatchers.any()))
                .thenReturn(reactor.core.publisher.Mono.just(new ch.nexsol.orthrusdast.http.ScanHttpResponse(
                        org.springframework.http.HttpStatus.OK, new org.springframework.http.HttpHeaders(), "", 0L)));

        ScanEngine engine = new ScanEngine(List.of(mockScanner), mockHttpClient);

        // Create 20 operations
        Operation op = new Operation("http://localhost", "GET", Map.of(), Map.of(), null, List.of(), List.of(), null, null, null);
        List<Operation> operations = java.util.stream.IntStream.range(0, 20)
                .mapToObj(i -> op)
                .toList();

        // Concurrency set to 5
        ScanConfiguration config = new ScanConfiguration(
                List.of(), List.of(), 5, 5000, 10000, false, "json", null, null, "en", false, GatewayType.AUTO, null, null
        );

        ch.nexsol.orthrusdast.ingestion.EndpointDiscoverer mockDiscoverer = new ch.nexsol.orthrusdast.ingestion.EndpointDiscoverer() {
            @Override
            public String getId() { return "mock-disc"; }
            @Override
            public reactor.core.publisher.Mono<List<Operation>> discover(String target, String overrideHost, ScanConfiguration cfg) {
                return reactor.core.publisher.Mono.just(operations);
            }
        };

        List<ch.nexsol.orthrusdast.model.ScanAttempt> attempts = engine.runScan(mockDiscoverer, "http://localhost", null, config).collectList().block();

        assertNotNull(attempts);
        assertEquals(20, attempts.size());
        
        // Assert max concurrency is bounded close to configured value
        assertTrue(maxScans.get() >= 5 && maxScans.get() <= 6, "Expected max concurrency around 5, but was " + maxScans.get());
    }
}

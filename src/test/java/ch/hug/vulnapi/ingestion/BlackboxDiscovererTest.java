package ch.hug.vulnapi.ingestion;

import org.junit.jupiter.api.Test;
import ch.hug.vulnapi.model.SecurityScheme;
import static org.junit.jupiter.api.Assertions.*;
import reactor.test.StepVerifier;

class BlackboxDiscovererTest {

    @Test
    void testDiscoverRestrictedDomain() {
        BlackboxDiscoverer discoverer = new BlackboxDiscoverer();
        // Since it's a component now, we would normally use @SpringBootTest or set properties manually
        // For a simple test, we just verify it doesn't crash on a bad URL
        
        StepVerifier.create(discoverer.discover("http://invalid-local-domain-that-does-not-exist.test", null, null))
            .assertNext(operations -> assertTrue(operations.isEmpty() || operations.size() == 1))
            .verifyComplete();
    }
}

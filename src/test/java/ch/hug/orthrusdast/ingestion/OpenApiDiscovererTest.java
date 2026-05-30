package ch.hug.orthrusdast.ingestion;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import reactor.test.StepVerifier;

class OpenApiDiscovererTest {

    @Test
    void testDiscoverEmptySpec() {
        OpenApiDiscoverer discoverer = new OpenApiDiscoverer();
        
        StepVerifier.create(discoverer.discover("invalid-url", null, null))
            .assertNext(operations -> assertTrue(operations.isEmpty()))
            .verifyComplete();
    }
}

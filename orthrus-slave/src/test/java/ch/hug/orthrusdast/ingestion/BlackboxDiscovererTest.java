package ch.hug.orthrusdast.ingestion;

import org.junit.jupiter.api.Test;
import ch.hug.orthrusdast.model.SecurityScheme;
import static org.junit.jupiter.api.Assertions.*;
import reactor.test.StepVerifier;

import ch.hug.orthrusdast.config.OrthrusProperties;

public class BlackboxDiscovererTest {

    @Test
    public void testBlackboxCrawler() {
        BlackboxDiscoverer discoverer = new BlackboxDiscoverer(new OrthrusProperties());
        // Since it's a component now, we would normally use @SpringBootTest or set properties manually
        // For a simple test, we just verify it doesn't crash on a bad URL
        
        StepVerifier.create(discoverer.discover("http://invalid-local-domain-that-does-not-exist.test", null, null))
            .assertNext(operations -> assertTrue(operations.isEmpty() || operations.size() == 1))
            .verifyComplete();
    }
}

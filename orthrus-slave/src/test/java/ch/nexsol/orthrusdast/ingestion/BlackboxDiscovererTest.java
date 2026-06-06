package ch.nexsol.orthrusdast.ingestion;

import org.junit.jupiter.api.Test;
import ch.nexsol.orthrusdast.model.SecurityScheme;
import static org.junit.jupiter.api.Assertions.*;
import reactor.test.StepVerifier;

import ch.nexsol.orthrusdast.config.OrthrusProperties;

public class BlackboxDiscovererTest {

    @Test
    public void testBlackboxCrawler() {
        BlackboxDiscoverer discoverer = new BlackboxDiscoverer(new OrthrusProperties());
        // Since it's a component now, we would normally use @SpringBootTest or set properties manually
        // For a simple test, we just verify it doesn't crash on a bad URL
        
        StepVerifier.create(discoverer.discover("http://invalid-local-domain-that-does-not-exist.test", null))
            .assertNext(operations -> assertTrue(operations.isEmpty() || operations.size() == 1))
            .verifyComplete();
    }
}

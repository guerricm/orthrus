package ch.nexsol.orthrusdast.ingestion;

import org.junit.jupiter.api.Test;
import reactor.test.StepVerifier;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CurlDiscovererTest {

    @Test
    void testGetId() {
        CurlDiscoverer discoverer = new CurlDiscoverer();
        assertEquals("curl", discoverer.getId());
    }

    @Test
    void testDiscoverSimpleUrl() {
        CurlDiscoverer discoverer = new CurlDiscoverer();
        StepVerifier.create(discoverer.discover("http://example.com/api", null))
            .assertNext(ops -> {
                assertEquals(1, ops.size());
                assertEquals("http://example.com/api", ops.get(0).url());
                assertEquals("GET", ops.get(0).method());
            })
            .verifyComplete();
    }
}

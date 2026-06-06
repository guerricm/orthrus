package ch.nexsol.orthrusdast.ingestion;

import org.junit.jupiter.api.Test;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.test.StepVerifier;

import static org.junit.jupiter.api.Assertions.assertEquals;

class WellKnownDiscovererTest {

    @Test
    void testGetId() {
        WellKnownDiscoverer discoverer = new WellKnownDiscoverer(org.mockito.Mockito.mock(ch.nexsol.orthrusdast.http.ScanHttpClient.class));
        assertEquals("well-known", discoverer.getId());
    }

    @Test
    void testDiscoverInvalidUrl() {
        ch.nexsol.orthrusdast.http.ScanHttpClient mockClient = org.mockito.Mockito.mock(ch.nexsol.orthrusdast.http.ScanHttpClient.class);
        org.mockito.Mockito.when(mockClient.send(org.mockito.ArgumentMatchers.any()))
            .thenReturn(reactor.core.publisher.Mono.just(new ch.nexsol.orthrusdast.http.ScanHttpResponse(org.springframework.http.HttpStatus.NOT_FOUND, new org.springframework.http.HttpHeaders(), "", 0L)));

        WellKnownDiscoverer discoverer = new WellKnownDiscoverer(mockClient);
        StepVerifier.create(discoverer.discover("http://invalid-url:9999", null))
            .assertNext(ops -> org.junit.jupiter.api.Assertions.assertTrue(ops.isEmpty()))
            .verifyComplete();
    }
}

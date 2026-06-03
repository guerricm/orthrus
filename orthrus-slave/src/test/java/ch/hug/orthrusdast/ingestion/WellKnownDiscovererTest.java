package ch.hug.orthrusdast.ingestion;

import org.junit.jupiter.api.Test;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.test.StepVerifier;

import static org.junit.jupiter.api.Assertions.assertEquals;

class WellKnownDiscovererTest {

    @Test
    void testGetId() {
        WellKnownDiscoverer discoverer = new WellKnownDiscoverer(org.mockito.Mockito.mock(ch.hug.orthrusdast.http.ScanHttpClient.class));
        assertEquals("well-known", discoverer.getId());
    }

    @Test
    void testDiscoverInvalidUrl() {
        ch.hug.orthrusdast.http.ScanHttpClient mockClient = org.mockito.Mockito.mock(ch.hug.orthrusdast.http.ScanHttpClient.class);
        org.mockito.Mockito.when(mockClient.send(org.mockito.ArgumentMatchers.any()))
            .thenReturn(reactor.core.publisher.Mono.just(new ch.hug.orthrusdast.http.ScanHttpResponse(org.springframework.http.HttpStatus.NOT_FOUND, new org.springframework.http.HttpHeaders(), "", 0L)));

        WellKnownDiscoverer discoverer = new WellKnownDiscoverer(mockClient);
        StepVerifier.create(discoverer.discover("http://invalid-url:9999", null, null))
            .assertNext(ops -> org.junit.jupiter.api.Assertions.assertTrue(ops.isEmpty()))
            .verifyComplete();
    }
}

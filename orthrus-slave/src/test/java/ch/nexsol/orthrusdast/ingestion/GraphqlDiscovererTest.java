package ch.nexsol.orthrusdast.ingestion;

import org.junit.jupiter.api.Test;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.test.StepVerifier;

import static org.junit.jupiter.api.Assertions.assertEquals;

class GraphqlDiscovererTest {

    @Test
    void testGetId() {
        GraphqlDiscoverer discoverer = new GraphqlDiscoverer(org.mockito.Mockito.mock(ch.nexsol.orthrusdast.http.ScanHttpClient.class));
        assertEquals("graphql", discoverer.getId());
    }

    @Test
    void testDiscoverInvalidUrl() {
        ch.nexsol.orthrusdast.http.ScanHttpClient mockClient = org.mockito.Mockito.mock(ch.nexsol.orthrusdast.http.ScanHttpClient.class);
        org.mockito.Mockito.when(mockClient.send(org.mockito.ArgumentMatchers.any()))
            .thenReturn(reactor.core.publisher.Mono.just(new ch.nexsol.orthrusdast.http.ScanHttpResponse(org.springframework.http.HttpStatus.NOT_FOUND, new org.springframework.http.HttpHeaders(), "", 0L)));
            
        GraphqlDiscoverer discoverer = new GraphqlDiscoverer(mockClient);
        StepVerifier.create(discoverer.discover("http://invalid-url:9999/graphql", null, null))
            .assertNext(ops -> org.junit.jupiter.api.Assertions.assertTrue(ops.isEmpty()))
            .verifyComplete();
    }
}

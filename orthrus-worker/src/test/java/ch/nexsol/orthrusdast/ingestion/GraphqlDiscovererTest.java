package ch.nexsol.orthrusdast.ingestion;

import org.junit.jupiter.api.Test;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.test.StepVerifier;

import static org.junit.jupiter.api.Assertions.assertEquals;

import ch.nexsol.orthrusdast.http.ScanHttpClient;
import ch.nexsol.orthrusdast.http.ScanHttpResponse;
import org.junit.jupiter.api.Assertions;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import reactor.core.publisher.Mono;

class GraphqlDiscovererTest {

	@Test
	void testGetId() {
		GraphqlDiscoverer discoverer = new GraphqlDiscoverer(Mockito.mock(ScanHttpClient.class));
		assertEquals("graphql", discoverer.getId());
	}

	@Test
	void testDiscoverInvalidUrl() {
		ScanHttpClient mockClient = Mockito.mock(ScanHttpClient.class);
		Mockito.when(mockClient.send(ArgumentMatchers.any()))
			.thenReturn(Mono.just(new ScanHttpResponse(HttpStatus.NOT_FOUND, new HttpHeaders(), "", 0L)));

		GraphqlDiscoverer discoverer = new GraphqlDiscoverer(mockClient);
		StepVerifier.create(discoverer.discover("http://invalid-url:9999/graphql", null))
			.assertNext(ops -> Assertions.assertTrue(ops.isEmpty()))
			.verifyComplete();
	}

}

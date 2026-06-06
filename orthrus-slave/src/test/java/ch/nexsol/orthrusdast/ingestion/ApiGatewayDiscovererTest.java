package ch.nexsol.orthrusdast.ingestion;

import ch.nexsol.orthrusdast.config.OrthrusProperties;
import ch.nexsol.orthrusdast.model.GatewayType;
import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.ScanConfiguration;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.test.StepVerifier;

import java.io.IOException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ApiGatewayDiscovererTest {

    private MockWebServer mockWebServer;
    private ApiGatewayDiscoverer discoverer;

    @BeforeEach
    void setUp() throws IOException {
        mockWebServer = new MockWebServer();
        mockWebServer.start();
        ch.nexsol.orthrusdast.ingestion.BlackboxDiscoverer mockBlackbox = new ch.nexsol.orthrusdast.ingestion.BlackboxDiscoverer(
                new OrthrusProperties()) {
            @Override
            public reactor.core.publisher.Mono<List<Operation>> discover(String target, ch.nexsol.orthrusdast.model.ScanConfiguration config) {
                Operation op = new Operation(target, "GET", java.util.Map.of(), java.util.Map.of(), null, List.of(),
                        List.of(), null);
                return reactor.core.publisher.Mono.just(List.of(op));
            }
        };
        discoverer = new ApiGatewayDiscoverer(mockBlackbox);
    }

    @AfterEach
    void tearDown() throws IOException {
        mockWebServer.shutdown();
    }

    @Test
    void testDiscover_KongGateway() {
        String url = mockWebServer.url("/").toString();

        mockWebServer.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                if (request.getPath().equals("/routes")) {
                    return new MockResponse().setResponseCode(200)
                            .setHeader("Content-Type", "application/json")
                            .setBody(
                                    "{\"data\": [{\"paths\": [\"/api/v1/users\"], \"methods\": [\"GET\", \"POST\"]}]}");
                }
                return new MockResponse().setResponseCode(404);
            }
        });

        ScanConfiguration config = new ScanConfiguration(
                List.of(), List.of(), 10, 5000, 10000, false, "json", null, null, "en", false, GatewayType.KONG, null,
                null, null, null);

        StepVerifier.create(discoverer.discover(url, config))
                .assertNext(operations -> {
                    assertEquals(1, operations.size());
                    assertTrue(operations.stream().anyMatch(o -> o.url().endsWith("/api/v1/users")));
                })
                .verifyComplete();
    }

    @Test
    void testDiscover_TraefikGateway() {
        String url = mockWebServer.url("/").toString();

        mockWebServer.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                if (request.getPath().equals("/api/http/routers")) {
                    return new MockResponse().setResponseCode(200)
                            .setHeader("Content-Type", "application/json")
                            .setBody("[{\"rule\": \"PathPrefix(`/api/v2/orders`)\"}]");
                }
                return new MockResponse().setResponseCode(404);
            }
        });

        ScanConfiguration config = new ScanConfiguration(
                List.of(), List.of(), 10, 5000, 10000, false, "json", null, null, "en", false, GatewayType.TRAEFIK,
                "api.traefik.internal", null, null, null);

        StepVerifier.create(discoverer.discover(url, config))
                .assertNext(operations -> {
                    assertFalse(operations.isEmpty());
                    assertEquals(1, operations.size());
                    Operation op = operations.get(0);
                    assertTrue(op.url().endsWith("/api/v2/orders"));
                    // Traefik adds default methods if not specified
                    assertEquals("GET", op.method());
                })
                .verifyComplete();
    }

    @Test
    void testDiscover_KubernetesIngress_WithToken() {
        String url = mockWebServer.url("/").toString();

        mockWebServer.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                if (!"Bearer test-k8s-token".equals(request.getHeader("Authorization"))) {
                    return new MockResponse().setResponseCode(401);
                }
                if (request.getPath().equals("/apis/networking.k8s.io/v1/ingresses")) {
                    return new MockResponse().setResponseCode(200)
                            .setHeader("Content-Type", "application/json")
                            .setBody(
                                    "{\"items\": [{\"spec\": {\"rules\": [{\"host\": \"example.com\", \"http\": {\"paths\": [{\"path\": \"/login\"}]}}]}}]}");
                }
                return new MockResponse().setResponseCode(404);
            }
        });

        ScanConfiguration config = new ScanConfiguration(
                List.of(), List.of(), 10, 5000, 10000, false, "json", null, null, "en", false, GatewayType.K8S, null,
                "test-k8s-token", null, null);

        StepVerifier.create(discoverer.discover(url, config))
                .assertNext(operations -> {
                    assertEquals(1, operations.size());
                    assertTrue(operations.get(0).url().endsWith("/login"));
                })
                .verifyComplete();
    }
}

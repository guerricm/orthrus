package ch.nexsol.orthrusdast.auth;

import ch.nexsol.orthrusdast.model.OAuth2Config;
import ch.nexsol.orthrusdast.model.SecurityScheme;
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
import static org.junit.jupiter.api.Assertions.assertTrue;

class OAuth2TokenFetcherTest {

    private MockWebServer mockWebServer;
    private OAuth2TokenFetcher fetcher;
    private String tokenUrl;

    @BeforeEach
    void setUp() throws IOException {
        mockWebServer = new MockWebServer();
        mockWebServer.start();
        tokenUrl = mockWebServer.url("/token").toString();
        fetcher = new OAuth2TokenFetcher();
    }

    @AfterEach
    void tearDown() throws IOException {
        mockWebServer.shutdown();
    }

    @Test
    void testFetchTokens_Success() {
        mockWebServer.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                String body = request.getBody().readUtf8();
                if (body.contains("username=admin")) {
                    return new MockResponse().setResponseCode(200).setHeader("Content-Type", "application/json")
                            .setBody("{\"access_token\": \"PRIMARY_TOKEN\", \"token_type\": \"Bearer\"}");
                } else if (body.contains("username=user")) {
                    return new MockResponse().setResponseCode(200).setHeader("Content-Type", "application/json")
                            .setBody("{\"access_token\": \"SECONDARY_TOKEN\", \"token_type\": \"Bearer\"}");
                }
                return new MockResponse().setResponseCode(400);
            }
        });

        OAuth2Config config = new OAuth2Config(
                tokenUrl, "test-client", "test-secret", "password", List.of("admin:pass", "user:pass")
        );

        StepVerifier.create(fetcher.fetchTokens(config))
                .assertNext(tokens -> {
                    assertEquals(2, tokens.size());
                    assertEquals("PRIMARY_TOKEN", tokens.get(0).value());
                    assertEquals("SECONDARY_TOKEN", tokens.get(1).value());
                })
                .verifyComplete();
    }

    @Test
    void testFetchTokens_EmptyCredentials() {
        OAuth2Config config = new OAuth2Config(
                tokenUrl, "test-client", "test-secret", "password", List.of()
        );

        StepVerifier.create(fetcher.fetchTokens(config))
                .assertNext(tokens -> assertTrue(tokens.isEmpty()))
                .verifyComplete();
    }
}

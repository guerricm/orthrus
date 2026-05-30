package ch.hug.vulnapi.scanner;

import ch.hug.vulnapi.http.ScanHttpClient;
import ch.hug.vulnapi.model.Operation;
import ch.hug.vulnapi.model.ScanConfiguration;
import ch.hug.vulnapi.model.SecurityScheme;
import ch.hug.vulnapi.model.Vulnerability;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.reactive.function.client.WebClient;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class ScannerIntegrationTests {

    private MockWebServer mockWebServer;
    private ScanHttpClient httpClient;
    private String baseUrl;

    @BeforeEach
    void setUp() throws IOException {
        mockWebServer = new MockWebServer();
        mockWebServer.start();
        baseUrl = mockWebServer.url("/").toString();
        // Remove trailing slash to mimic standard URL format
        if (baseUrl.endsWith("/")) {
            baseUrl = baseUrl.substring(0, baseUrl.length() - 1);
        }
        httpClient = new ScanHttpClient(WebClient.create());
    }

    @AfterEach
    void tearDown() throws IOException {
        mockWebServer.shutdown();
    }

    @Test
    void testSqlInjectionScanner() {
        SqlInjectionScanner scanner = new SqlInjectionScanner(httpClient);
        
        Operation op = new Operation(baseUrl + "/users", "GET", Map.<String, String>of(), Map.of("id", "1"), null, List.<String>of(), List.<String>of(), null);

        mockWebServer.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                if (request.getPath().contains("OR")) {
                    return new MockResponse().setResponseCode(500).setBody("SQL syntax error near '' OR '1'='1'");
                }
                return new MockResponse().setResponseCode(200).setBody("{\"status\": \"ok\"}");
            }
        });

        List<Vulnerability> vulns = scanner.scan(op).collectList().block();
        assertThat(vulns).isNotEmpty();
        assertThat(vulns.get(0).cwe().getId()).isEqualTo(89);
    }

    @Test
    void testXssScanner() {
        XssScanner scanner = new XssScanner(httpClient);

        Operation op = new Operation(baseUrl + "/search", "GET", Map.<String, String>of(), Map.of("q", "test"), null, List.<String>of(), List.<String>of(), null);

        mockWebServer.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                return new MockResponse().setResponseCode(200).setHeader("Content-Type", "text/html").setBody("Results for <script>alert('XSS_VULNAPI_TEST')</script>");
            }
        });

        List<Vulnerability> vulns = scanner.scan(op).collectList().block();
        assertThat(vulns).isNotEmpty();
        // Since it checks query and 3 headers, we might get multiple vulns. We just verify at least one XSS is found.
        assertThat(vulns.get(0).cwe().getId()).isEqualTo(79);
    }

    @Test
    void testSstiScanner() {
        SstiScanner scanner = new SstiScanner(httpClient);

        Operation op = new Operation(baseUrl + "/template", "GET", Map.<String, String>of(), Map.of("name", "John"), null, List.<String>of(), List.<String>of(), null);

        mockWebServer.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                return new MockResponse().setResponseCode(200).setBody("Hello 49");
            }
        });

        List<Vulnerability> vulns = scanner.scan(op).collectList().block();
        assertThat(vulns).isNotEmpty();
        assertThat(vulns.get(0).cwe().getId()).isEqualTo(1336);
    }

    @Test
    void testCleartextScanner() {
        CleartextScanner scanner = new CleartextScanner(httpClient);

        Operation httpOp = new Operation("http://api.example.com/data", "GET", Map.<String, String>of(), Map.<String, String>of(), null, List.<String>of(), List.<String>of(), null);
        List<Vulnerability> vulns = scanner.scan(httpOp).collectList().block();
        assertThat(vulns).hasSize(1);
        assertThat(vulns.get(0).cwe().getId()).isEqualTo(319);
    }

    @Test
    void testContentTypeSpoofingScanner() {
        ContentTypeSpoofingScanner scanner = new ContentTypeSpoofingScanner(httpClient);

        Operation op = new Operation(baseUrl + "/data", "POST", Map.of("Content-Type", "application/json"), Map.<String, String>of(), "{\"key\": \"value\"}", List.<String>of(), List.<String>of(), null);

        mockWebServer.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                return new MockResponse().setResponseCode(200).setBody("root:x:0:0");
            }
        });

        List<Vulnerability> vulns = scanner.scan(op).collectList().block();
        assertThat(vulns).hasSize(1);
        assertThat(vulns.get(0).cwe().getId()).isEqualTo(611);
    }

    @Test
    void testCrossUserBolaScanner() {
        CrossUserBolaScanner scanner = new CrossUserBolaScanner(httpClient);

        SecurityScheme userA = SecurityScheme.bearer("TOKEN_A");
        SecurityScheme userB = SecurityScheme.bearer("TOKEN_B");
        ScanConfiguration config = new ScanConfiguration(List.<String>of(), List.<String>of(), 10, 5000, 10000, false, "json", userA, userB, "en", false);

        Operation op = new Operation(baseUrl + "/invoices/123", "GET", Map.<String, String>of(), Map.<String, String>of(), null, List.of("bearerAuth"), List.<String>of(), userA);

        mockWebServer.setDispatcher(new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                return new MockResponse().setResponseCode(200).setBody("{\"invoiceId\": 123, \"amount\": 100}");
            }
        });

        List<Vulnerability> vulns = scanner.scan(op, config).collectList().block();
        assertThat(vulns).hasSize(1);
        assertThat(vulns.get(0).cwe().getId()).isEqualTo(639);
    }
}

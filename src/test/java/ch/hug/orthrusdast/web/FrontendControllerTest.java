package ch.hug.orthrusdast.web;

import ch.hug.orthrusdast.auth.OAuth2TokenFetcher;
import ch.hug.orthrusdast.engine.ScanResultService;
import ch.hug.orthrusdast.engine.ScanService;
import ch.hug.orthrusdast.engine.StatisticsService;
import ch.hug.orthrusdast.report.PdfReportGenerator;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import java.util.List;
import static org.mockito.Mockito.when;

@org.junit.jupiter.api.extension.ExtendWith(org.mockito.junit.jupiter.MockitoExtension.class)
class FrontendControllerTest {

    @org.mockito.Mock
    private ScanService scanService;

    @org.mockito.Mock
    private ScanResultService scanResultService;

    @org.mockito.Mock
    private PdfReportGenerator pdfReportGenerator;

    @org.mockito.Mock
    private ch.hug.orthrusdast.auth.OAuth2TokenFetcher tokenFetcher;

    @org.mockito.Mock
    private StatisticsService statisticsService;

    private FrontendController controller;

    @org.junit.jupiter.api.BeforeEach
    void setUp() {
        controller = new FrontendController(scanService, scanResultService, pdfReportGenerator, tokenFetcher, statisticsService);
    }

    @Test
    void testGetIndexPage() {
        when(scanResultService.findAll()).thenReturn(reactor.core.publisher.Flux.empty());
        when(scanService.getAvailableDiscoverers()).thenReturn(java.util.List.of("openapi", "graphql"));

        org.springframework.ui.Model model = new org.springframework.ui.ConcurrentModel();
        String viewName = controller.index(model).block();
        org.junit.jupiter.api.Assertions.assertEquals("home", viewName);
        org.junit.jupiter.api.Assertions.assertTrue(model.containsAttribute("discoverers"));
    }

    @Test
    void testGetResultsPage() {
        when(scanResultService.getHistory(0, 10)).thenReturn(reactor.core.publisher.Flux.empty());

        org.springframework.ui.Model model = new org.springframework.ui.ConcurrentModel();
        String viewName = controller.listScans(model).block();
        org.junit.jupiter.api.Assertions.assertEquals("scans/list", viewName);
        org.junit.jupiter.api.Assertions.assertTrue(model.containsAttribute("history"));
    }
}

package ch.nexsol.orthrusdast.web;

import ch.nexsol.orthrusdast.auth.OAuth2TokenFetcher;
import ch.nexsol.orthrusdast.engine.ScanResultService;
// ch.nexsol.orthrusdast.engine.ScanService removed
import ch.nexsol.orthrusdast.engine.StatisticsService;
import ch.nexsol.orthrusdast.report.PdfReportGenerator;
import ch.nexsol.orthrusdast.report.HtmlReportGenerator;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import java.util.List;
import static org.mockito.Mockito.when;

@org.junit.jupiter.api.extension.ExtendWith(org.mockito.junit.jupiter.MockitoExtension.class)
class FrontendControllerTest {

	// ScanService removed

	@org.mockito.Mock
	private ScanResultService scanResultService;

	@org.mockito.Mock
	private PdfReportGenerator pdfReportGenerator;

	@org.mockito.Mock
	private HtmlReportGenerator htmlReportGenerator;

	@org.mockito.Mock
	private ch.nexsol.orthrusdast.auth.OAuth2TokenFetcher tokenFetcher;

	@org.mockito.Mock
	private StatisticsService statisticsService;

	@org.mockito.Mock
	private ch.nexsol.orthrusdast.repository.ScanJobRepository scanJobRepository;

	@org.mockito.Mock
	private ch.nexsol.orthrusdast.repository.SlaveNodeRepository slaveNodeRepository;

	private tools.jackson.databind.ObjectMapper objectMapper = new tools.jackson.databind.ObjectMapper();

	@org.mockito.Mock
	private ch.nexsol.orthrusdast.sse.JobEventPublisher jobEventPublisher;

	@org.mockito.Mock
	private org.springframework.beans.factory.ObjectProvider<org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository> clientRegistrations;

	@org.mockito.Mock
	private ch.nexsol.orthrusdast.repository.TestPlanRepository testPlanRepository;

	private FrontendController controller;

	@org.junit.jupiter.api.BeforeEach
	void setUp() {
		controller = new FrontendController(scanResultService, pdfReportGenerator, htmlReportGenerator, tokenFetcher,
				statisticsService, scanJobRepository, testPlanRepository, slaveNodeRepository, objectMapper,
				jobEventPublisher, clientRegistrations);
	}

	@Test
	void testGetIndexPage() {
		when(scanResultService.findAll()).thenReturn(reactor.core.publisher.Flux.empty());
		when(scanResultService.findAll()).thenReturn(reactor.core.publisher.Flux.empty());

		org.springframework.ui.Model model = new org.springframework.ui.ConcurrentModel();
		String viewName = controller.index(model).block();
		org.junit.jupiter.api.Assertions.assertEquals("home", viewName);
		org.junit.jupiter.api.Assertions.assertTrue(model.containsAttribute("discoverers"));
	}

	@Test
	void testGetResultsPage() {
		when(scanJobRepository.findAllByOrderByCreatedAtDesc(
				org.mockito.ArgumentMatchers.any(org.springframework.data.domain.Pageable.class)))
			.thenReturn(reactor.core.publisher.Flux.empty());

		org.springframework.ui.Model model = new org.springframework.ui.ConcurrentModel();
		String viewName = controller.listScans(model).block();
		org.junit.jupiter.api.Assertions.assertEquals("scans/list", viewName);
		org.junit.jupiter.api.Assertions.assertTrue(model.containsAttribute("history"));
	}

}

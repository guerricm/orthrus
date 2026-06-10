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

import ch.nexsol.orthrusdast.repository.ScanJobRepository;
import ch.nexsol.orthrusdast.repository.SlaveNodeRepository;
import ch.nexsol.orthrusdast.repository.TestPlanRepository;
import ch.nexsol.orthrusdast.sse.JobEventPublisher;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.data.domain.Pageable;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.ui.ConcurrentModel;
import org.springframework.ui.Model;
import reactor.core.publisher.Flux;

@ExtendWith(MockitoExtension.class)
class FrontendControllerTest {

	// ScanService removed

	@Mock
	private ScanResultService scanResultService;

	@Mock
	private PdfReportGenerator pdfReportGenerator;

	@Mock
	private HtmlReportGenerator htmlReportGenerator;

	@Mock
	private OAuth2TokenFetcher tokenFetcher;

	@Mock
	private StatisticsService statisticsService;

	@Mock
	private ScanJobRepository scanJobRepository;

	@Mock
	private SlaveNodeRepository slaveNodeRepository;

	private tools.jackson.databind.ObjectMapper objectMapper = new tools.jackson.databind.ObjectMapper();

	@Mock
	private JobEventPublisher jobEventPublisher;

	@Mock
	private ObjectProvider<ReactiveClientRegistrationRepository> clientRegistrations;

	@Mock
	private TestPlanRepository testPlanRepository;

	private FrontendController controller;

	@BeforeEach
	void setUp() {
		controller = new FrontendController(scanResultService, pdfReportGenerator, htmlReportGenerator, tokenFetcher,
				statisticsService, scanJobRepository, testPlanRepository, slaveNodeRepository, objectMapper,
				jobEventPublisher, clientRegistrations);
	}

	@Test
	void testGetIndexPage() {
		when(scanResultService.findAll()).thenReturn(Flux.empty());
		when(scanResultService.findAll()).thenReturn(Flux.empty());

		Model model = new ConcurrentModel();
		String viewName = controller.index(model).block();
		Assertions.assertEquals("home", viewName);
		Assertions.assertTrue(model.containsAttribute("discoverers"));
	}

	@Test
	void testGetResultsPage() {
		when(scanJobRepository.findAllByOrderByCreatedAtDesc(ArgumentMatchers.any(Pageable.class)))
			.thenReturn(Flux.empty());

		Model model = new ConcurrentModel();
		String viewName = controller.listScans(model).block();
		Assertions.assertEquals("scans/list", viewName);
		Assertions.assertTrue(model.containsAttribute("history"));
	}

}

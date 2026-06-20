package ch.nexsol.orthrusdast.web;

import ch.nexsol.orthrusdast.engine.ScanResultService;
import ch.nexsol.orthrusdast.repository.ScanJobRepository;
import ch.nexsol.orthrusdast.repository.SlaveNodeRepository;
import ch.nexsol.orthrusdast.repository.TestPlanRepository;
import ch.nexsol.orthrusdast.sse.JobEventPublisher;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.Pageable;
import org.springframework.ui.ConcurrentModel;
import org.springframework.ui.Model;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Flux;

import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ScanViewControllerTest {

	@Mock
	private ScanJobRepository scanJobRepository;

	@Mock
	private ScanResultService scanResultService;

	@Mock
	private TestPlanRepository testPlanRepository;

	@Mock
	private SlaveNodeRepository slaveNodeRepository;

	@Mock
	private JobEventPublisher jobEventPublisher;

	private final tools.jackson.databind.ObjectMapper objectMapper = new tools.jackson.databind.ObjectMapper();

	private ScanViewController controller;

	@BeforeEach
	void setUp() {
		controller = new ScanViewController(scanJobRepository, scanResultService, testPlanRepository,
				slaveNodeRepository, jobEventPublisher, objectMapper, WebClient.builder());
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

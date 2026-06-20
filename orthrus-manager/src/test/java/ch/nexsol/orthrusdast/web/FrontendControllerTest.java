package ch.nexsol.orthrusdast.web;

import ch.nexsol.orthrusdast.engine.ScanResultService;
import ch.nexsol.orthrusdast.engine.StatisticsService;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.ui.ConcurrentModel;
import org.springframework.ui.Model;
import reactor.core.publisher.Flux;

import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class FrontendControllerTest {

	@Mock
	private ScanResultService scanResultService;

	@Mock
	private StatisticsService statisticsService;

	@Mock
	private ObjectProvider<ReactiveClientRegistrationRepository> clientRegistrations;

	private FrontendController controller;

	@BeforeEach
	void setUp() {
		controller = new FrontendController(scanResultService, statisticsService, clientRegistrations);
	}

	@Test
	void testGetIndexPage() {
		when(scanResultService.findAll()).thenReturn(Flux.empty());

		Model model = new ConcurrentModel();
		String viewName = controller.index(model).block();
		Assertions.assertEquals("home", viewName);
		Assertions.assertTrue(model.containsAttribute("discoverers"));
	}

}

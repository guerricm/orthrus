package ch.nexsol.orthrusdast;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest(properties = { "spring.r2dbc.url=r2dbc:h2:mem:///testdb;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE",
		"spring.r2dbc.username=sa", "spring.r2dbc.password=" })
class OrthrusDastApplicationTests {

	@Test
	void contextLoads() {
		// Just checking that the Spring context (with WebFlux, Picocli, WebClient) loads
		// successfully
	}

}

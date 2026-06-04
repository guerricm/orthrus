package ch.nexsol.orthrusdast.scanner.oast;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.UUID;

/**
 * Mock implementation of OAST service for development.
 * In a real production deployment, this would use WebClient to hit an Interactsh server API
 * (registering with RSA keys and polling /poll).
 */
@Service
public class InteractshClient implements OastService {

    private static final Logger log = LoggerFactory.getLogger(InteractshClient.class);

    @Override
    public Mono<OastSession> createSession() {
        // Generate a random mocked interactsh domain
        String correlationId = UUID.randomUUID().toString().substring(0, 10).replace("-", "");
        String domain = correlationId + ".oast.local";
        log.debug("Created new OAST session: {}", domain);
        return Mono.just(new OastSession(correlationId, domain, "mock-secret"));
    }

    @Override
    public Flux<OastInteraction> pollInteractions(OastSession session) {
        // Mock polling: in a real scenario, this would GET /poll?id=correlationId&secret=secret
        log.debug("Polling OAST interactions for domain: {}", session.domain());
        return Flux.empty(); // Returns no interactions in the mock
    }
}

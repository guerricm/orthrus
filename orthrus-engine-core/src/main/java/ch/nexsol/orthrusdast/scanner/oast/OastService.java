package ch.nexsol.orthrusdast.scanner.oast;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;

public interface OastService {

    record OastSession(String correlationId, String domain, String secretKey) {}

    record OastInteraction(String protocol, String queryType, String rawRequest, String remoteAddress, Instant timestamp) {}

    /**
     * Registers a new unique domain for receiving Out-Of-Band interactions.
     */
    Mono<OastSession> createSession();

    /**
     * Polls interactions for a specific session.
     */
    Flux<OastInteraction> pollInteractions(OastSession session);
}

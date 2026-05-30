package ch.hug.vulnapi.ingestion;

import ch.hug.vulnapi.model.Operation;
import ch.hug.vulnapi.model.SecurityScheme;
import java.util.List;
import reactor.core.publisher.Mono;

/**
 * Interface for API discovery mechanisms.
 */
public interface EndpointDiscoverer {
    
    /**
     * @return the unique identifier of the discoverer
     */
    String getId();

    /**
     * Executes the discovery process.
     * @param target the target to discover (URL, OpenAPI spec, etc.)
     * @param overrideHost optional host to override
     * @param authScheme optional auth scheme to apply to discovered operations
     * @return a Mono emitting a List of discovered operations
     */
    Mono<List<Operation>> discover(String target, String overrideHost, SecurityScheme authScheme);
}

package ch.nexsol.orthrusdast.ingestion;

import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.ScanConfiguration;
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
     * @param config the scan configuration
     * @return a Mono emitting a List of discovered operations
     */
    Mono<List<Operation>> discover(String target, ScanConfiguration config);
}

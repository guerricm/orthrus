package ch.hug.orthrusdast.ingestion;

import ch.hug.orthrusdast.model.Operation;
import ch.hug.orthrusdast.model.SecurityScheme;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * "Discoverer" that just takes a single URL (like a curl command) and treats it as the only operation.
 */
@Component
public class CurlDiscoverer implements EndpointDiscoverer {

    private static final Logger log = LoggerFactory.getLogger(CurlDiscoverer.class);

    @Override
    public String getId() {
        return "curl";
    }

    @Override
    public Mono<List<Operation>> discover(String target, String overrideHost, SecurityScheme authScheme) {
        log.info("Registering single target for curl-like scan: {}", target);
        
        // Assume GET if not otherwise specified. Advanced curl-like usage (setting method/headers) 
        // would require parsing target string if it contained CLI-like flags, 
        // but for now we just take the URL as target.
        
        Operation op = Operation.simple(target, "GET").withAuth(authScheme);
        return Mono.just(List.of(op));
    }
}

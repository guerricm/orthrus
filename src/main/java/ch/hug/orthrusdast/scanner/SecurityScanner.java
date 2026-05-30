package ch.hug.orthrusdast.scanner;
import java.util.List;

import ch.hug.orthrusdast.model.Operation;
import ch.hug.orthrusdast.model.Vulnerability;
import reactor.core.publisher.Flux;

/**
 * Interface for all security scanners.
 */
public interface SecurityScanner {
    
    /**
     * @return the unique identifier of the scanner
     */
    String getId();

    /**
     * @return the human-readable name of the scanner
     */
    String getName();

    /**
     * Executes the scan on the given operation with context configuration.
     * @param operation the operation to scan
     * @param config the scan configuration
     * @return a Flux of found vulnerabilities
     */
    default Flux<Vulnerability> scan(Operation operation, ch.hug.orthrusdast.model.ScanConfiguration config) {
        return scan(operation);
    }

    /**
     * Executes the scan on the given operation.
     * @param operation the operation to scan
     * @return a Flux of found vulnerabilities
     */
    Flux<Vulnerability> scan(Operation operation);
}

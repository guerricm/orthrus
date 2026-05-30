package ch.hug.vulnapi.report;

import ch.hug.vulnapi.model.ScanResult;
import reactor.core.publisher.Mono;

import java.io.OutputStream;

/**
 * Common interface for all report generators.
 */
public interface ReportGenerator {
    
    /**
     * @return the format identifier (e.g., "json", "sarif", "html")
     */
    String getFormat();

    /**
     * Generates the report and writes it to the output stream.
     * @param result The scan result
     * @param output The output stream to write to
     * @return a Mono that completes when the report is fully written
     */
    Mono<Void> generateReport(ScanResult result, OutputStream output);
}

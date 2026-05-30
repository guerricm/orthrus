package ch.hug.orthrusdast.report;

import ch.hug.orthrusdast.model.ScanResult;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.io.OutputStream;

/**
 * Generates a detailed JSON report.
 */
@Component
public class JsonReportGenerator implements ReportGenerator {

    private static final Logger log = LoggerFactory.getLogger(JsonReportGenerator.class);
    private final ObjectMapper objectMapper;

    public JsonReportGenerator() {
        this.objectMapper = new ObjectMapper();
        this.objectMapper.registerModule(new JavaTimeModule());
        this.objectMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        this.objectMapper.enable(SerializationFeature.INDENT_OUTPUT);
    }

    /**
     * Gets the format identifier for this generator.
     *
     * @return the format string "json"
     */
    @Override
    public String getFormat() {
        return "json";
    }

    /**
     * Generates a JSON report from a ScanResult and writes it to the output stream.
     *
     * @param result the scan result containing vulnerabilities and execution attempts
     * @param output the output stream to write the JSON content to
     * @return a Mono signaling completion
     */
    @Override
    public Mono<Void> generateReport(ScanResult result, OutputStream output) {
        return Mono.fromRunnable(() -> {
            try {
                log.debug("Generating JSON report...");
                objectMapper.writeValue(output, result);
            } catch (Exception e) {
                log.error("Failed to generate JSON report", e);
                throw new RuntimeException("JSON generation failed", e);
            }
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }
}

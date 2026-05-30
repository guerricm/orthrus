package ch.hug.vulnapi.report;

import ch.hug.vulnapi.model.ScanResult;
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

    @Override
    public String getFormat() {
        return "json";
    }

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

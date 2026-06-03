package ch.hug.orthrusdast.scanner.payload;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class PayloadLoaderService {

    private static final Logger log = LoggerFactory.getLogger(PayloadLoaderService.class);
    
    // In-memory cache to avoid re-reading files on every scan
    private final Map<String, List<String>> payloadCache = new ConcurrentHashMap<>();

    /**
     * Retrieves payloads for a specific category (e.g., "sqli", "xss").
     * Tries to read from classpath:payloads/{category}.txt
     * Falls back to a default minimal list if the file is not found.
     */
    public Flux<String> getPayloads(String category) {
        if (payloadCache.containsKey(category)) {
            return Flux.fromIterable(payloadCache.get(category));
        }

        return Flux.defer(() -> {
            List<String> payloads = new ArrayList<>();
            try {
                ClassPathResource resource = new ClassPathResource("payloads/" + category + ".txt");
                if (resource.exists()) {
                    try (BufferedReader reader = new BufferedReader(
                            new InputStreamReader(resource.getInputStream(), StandardCharsets.UTF_8))) {
                        String line;
                        while ((line = reader.readLine()) != null) {
                            String trimmed = line.trim();
                            // Ignore comments and empty lines
                            if (!trimmed.isEmpty() && !trimmed.startsWith("#")) {
                                payloads.add(trimmed);
                            }
                        }
                    }
                    log.info("Loaded {} payloads for category '{}'", payloads.size(), category);
                } else {
                    log.warn("Payload file not found for category '{}'. Using fallback payloads.", category);
                    payloads = getFallbackPayloads(category);
                }
            } catch (Exception e) {
                log.error("Failed to load payloads for category '{}': {}", category, e.getMessage());
                payloads = getFallbackPayloads(category);
            }
            
            payloadCache.put(category, payloads);
            return Flux.fromIterable(payloads);
        });
    }

    private List<String> getFallbackPayloads(String category) {
        return switch (category.toLowerCase()) {
            case "sqli" -> List.of("' OR '1'='1", "1; SLEEP(5)--", "1' WAITFOR DELAY '0:0:5'--");
            case "xss" -> List.of("<script>alert('XSS')</script>", "\"><img src=x onerror=alert(1)>");
            case "cmd" -> List.of("; echo VULNERABLE", "$(sleep 5)");
            default -> List.of("test_payload");
        };
    }
}

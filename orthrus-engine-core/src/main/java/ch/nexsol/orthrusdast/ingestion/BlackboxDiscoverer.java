package ch.nexsol.orthrusdast.ingestion;

import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.SecurityScheme;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import org.springframework.core.io.ClassPathResource;
import org.springframework.web.reactive.function.client.WebClient;
import java.io.BufferedReader;
import java.io.InputStreamReader;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import ch.nexsol.orthrusdast.config.OrthrusProperties;

@Component
public class BlackboxDiscoverer implements EndpointDiscoverer {

    private static final Logger log = LoggerFactory.getLogger(BlackboxDiscoverer.class);

    private final OrthrusProperties properties;

    public BlackboxDiscoverer(OrthrusProperties properties) {
        this.properties = properties;
    }

    @Override
    public String getId() {
        return "blackbox";
    }

    @Override
    public Mono<List<Operation>> discover(String target, ch.nexsol.orthrusdast.model.ScanConfiguration config) {
        ch.nexsol.orthrusdast.model.SecurityScheme authScheme = config != null ? config.authScheme() : null;
        int maxDepth = properties.getDiscovery().getBlackboxMaxDepth();
        log.info("Starting black-box discovery from: {} (Max Depth: {})", target, maxDepth);
        
        return Mono.fromCallable(() -> {
            Set<String> visitedUrls = new HashSet<>();
            List<Operation> discoveredEndpoints = new ArrayList<>();
            String targetHost = extractHost(target);
            
            if (targetHost != null) {
                crawl(target, targetHost, 0, visitedUrls, discoveredEndpoints, authScheme);
            }
            
            log.info("Discovered {} endpoints via HTML crawling", discoveredEndpoints.size());
            return discoveredEndpoints;
        }).subscribeOn(Schedulers.boundedElastic())
        .flatMap(crawledEndpoints -> {
            log.info("Starting API Dictionary Fuzzing on {}", target);
            List<String> dictionary = new ArrayList<>();
            try (BufferedReader br = new BufferedReader(new InputStreamReader(new ClassPathResource("api-wordlist.txt").getInputStream()))) {
                String line;
                while ((line = br.readLine()) != null) {
                    if (!line.trim().isEmpty()) {
                        dictionary.add(line.trim());
                    }
                }
            } catch (Exception e) {
                log.warn("Could not load api-wordlist.txt: {}", e.getMessage());
            }

            if (dictionary.isEmpty()) {
                return Mono.just(crawledEndpoints);
            }

            String baseUrl = target.endsWith("/") ? target : target + "/";
            WebClient client = WebClient.builder().baseUrl(baseUrl).build();

            return Flux.fromIterable(dictionary)
                    .flatMap(path -> {
                        String cleanPath = path.startsWith("/") ? path.substring(1) : path;
                        return client.head().uri(cleanPath).exchangeToMono(response -> {
                            if (isValidResponse(response.statusCode().value())) return Mono.just(Operation.simple(baseUrl + cleanPath, "GET").withAuth(authScheme));
                            return Mono.<Operation>empty();
                        }).onErrorResume(e -> Mono.empty())
                        .switchIfEmpty(
                            client.get().uri(cleanPath).exchangeToMono(response -> {
                                if (isValidResponse(response.statusCode().value())) return Mono.just(Operation.simple(baseUrl + cleanPath, "GET").withAuth(authScheme));
                                return Mono.<Operation>empty();
                            }).onErrorResume(e -> Mono.empty())
                        ).switchIfEmpty(
                            client.post().uri(cleanPath).exchangeToMono(response -> {
                                if (isValidResponse(response.statusCode().value())) return Mono.just(Operation.simple(baseUrl + cleanPath, "POST").withAuth(authScheme));
                                return Mono.<Operation>empty();
                            }).onErrorResume(e -> Mono.empty())
                        );
                    }, 20) // concurrency of 20
                    .collectList()
                    .map(fuzzedEndpoints -> {
                        Set<String> urls = new HashSet<>();
                        List<Operation> combined = new ArrayList<>();
                        for (Operation op : crawledEndpoints) {
                            if (urls.add(op.url())) combined.add(op);
                        }
                        for (Operation op : fuzzedEndpoints) {
                            if (urls.add(op.url())) combined.add(op);
                        }
                        log.info("Discovered {} total endpoints after fuzzing", combined.size());
                        return combined;
                    });
        });
    }

    private String extractHost(String url) {
        try {
            return new URI(url).getHost();
        } catch (URISyntaxException e) {
            log.error("Invalid root URL: {}", url);
            return null;
        }
    }

    private boolean isValidResponse(int statusCode) {
        // Accept 2xx, 3xx, 400 Bad Request, 401 Unauthorized, 403 Forbidden, 415 Unsupported Media Type, and 5xx (Server Errors)
        return (statusCode >= 200 && statusCode < 400) ||
               (statusCode >= 500 && statusCode < 600) ||
               statusCode == 400 || statusCode == 401 || statusCode == 403 || statusCode == 415;
    }

    private void crawl(String url, String targetHost, int depth, Set<String> visitedUrls, List<Operation> discoveredEndpoints, SecurityScheme authScheme) {
        int maxDepth = properties.getDiscovery().getBlackboxMaxDepth();
        if (depth > maxDepth) {
            return;
        }
        if (visitedUrls.contains(url)) {
            return;
        }

        try {
            URI uri = new URI(url);
            if (!targetHost.equals(uri.getHost())) {
                return; // Strictly restrict to the initial target domain
            }
        } catch (URISyntaxException e) {
            return;
        }

        visitedUrls.add(url);
        log.debug("Crawling depth {}: {}", depth, url);

        try {
            int timeoutMs = properties.getDiscovery().getBlackboxTimeoutMs();
            Document doc = Jsoup.connect(url)
                    .timeout(timeoutMs)
                    .ignoreHttpErrors(true)
                    .ignoreContentType(true)
                    .get();
            
            // Register this page as an endpoint
            discoveredEndpoints.add(Operation.simple(url, "GET").withAuth(authScheme));

            // Extract Links
            Elements links = doc.select("a[href]");
            for (Element link : links) {
                String nextUrl = link.absUrl("href");
                if (nextUrl != null && !nextUrl.isEmpty()) {
                    crawl(nextUrl, targetHost, depth + 1, visitedUrls, discoveredEndpoints, authScheme);
                }
            }

            // Extract Forms
            Elements forms = doc.select("form");
            for (Element form : forms) {
                String actionUrl = form.absUrl("action");
                String method = form.attr("method").toUpperCase();
                if (method.isEmpty()) {
                    method = "GET";
                }
                if (actionUrl != null && !actionUrl.isEmpty()) {
                    discoveredEndpoints.add(Operation.simple(actionUrl, method).withAuth(authScheme));
                    // Follow form action as GET if applicable
                    if ("GET".equals(method)) {
                        crawl(actionUrl, targetHost, depth + 1, visitedUrls, discoveredEndpoints, authScheme);
                    }
                }
            }

        } catch (Exception e) {
            log.warn("Failed to fetch or parse URL {}: {}", url, e.getMessage());
        }
    }
}

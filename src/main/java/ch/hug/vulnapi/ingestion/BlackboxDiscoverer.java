package ch.hug.vulnapi.ingestion;

import ch.hug.vulnapi.model.Operation;
import ch.hug.vulnapi.model.SecurityScheme;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Component
public class BlackboxDiscoverer implements EndpointDiscoverer {

    private static final Logger log = LoggerFactory.getLogger(BlackboxDiscoverer.class);

    @Value("${orthrus.discovery.blackbox-max-depth:5}")
    private int maxDepth;
    
    @Value("${orthrus.discovery.blackbox-timeout-ms:5000}")
    private int timeoutMs;

    @Override
    public String getId() {
        return "blackbox";
    }

    @Override
    public Mono<List<Operation>> discover(String target, String overrideHost, SecurityScheme authScheme) {
        log.info("Starting black-box discovery from: {} (Max Depth: {})", target, maxDepth);
        
        return Mono.fromCallable(() -> {
            Set<String> visitedUrls = new HashSet<>();
            List<Operation> discoveredEndpoints = new ArrayList<>();
            String targetHost = extractHost(target);
            
            if (targetHost != null) {
                crawl(target, targetHost, 0, visitedUrls, discoveredEndpoints, authScheme);
            }
            
            log.info("Discovered {} endpoints via black-box crawling", discoveredEndpoints.size());
            return discoveredEndpoints;
        }).subscribeOn(Schedulers.boundedElastic());
    }

    private String extractHost(String url) {
        try {
            return new URI(url).getHost();
        } catch (URISyntaxException e) {
            log.error("Invalid root URL: {}", url);
            return null;
        }
    }

    private void crawl(String url, String targetHost, int depth, Set<String> visitedUrls, List<Operation> discoveredEndpoints, SecurityScheme authScheme) {
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
            // Using Jsoup for HTML parsing. 
            Document doc = Jsoup.connect(url).timeout(timeoutMs).get();
            
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

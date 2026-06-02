package ch.hug.orthrusdast.ingestion;

import ch.hug.orthrusdast.model.Operation;
import ch.hug.orthrusdast.model.ScanConfiguration;
import ch.hug.orthrusdast.model.GatewayType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Component
public class ApiGatewayDiscoverer implements EndpointDiscoverer {

    private static final Logger log = LoggerFactory.getLogger(ApiGatewayDiscoverer.class);
    
    private final BlackboxDiscoverer blackboxDiscoverer;

    public ApiGatewayDiscoverer(BlackboxDiscoverer blackboxDiscoverer) {
        this.blackboxDiscoverer = blackboxDiscoverer;
    }

    @Override
    public String getId() {
        return "gateway";
    }

    @Override
    public Mono<List<Operation>> discover(String target, String overrideHost, ScanConfiguration config) {
        log.info("Starting API Gateway Discovery on Admin URL: {}", target);
        
        GatewayType gatewayType = config.gatewayType() != null ? config.gatewayType() : GatewayType.AUTO;
        String appUrl = config.appUrl() != null ? config.appUrl() : target;
        
        // Ensure appUrl doesn't end with slash for cleaner concatenation
        if (appUrl.endsWith("/")) {
            appUrl = appUrl.substring(0, appUrl.length() - 1);
        }

        WebClient client = WebClient.builder().build();
        final String finalAppUrl = appUrl;

        Mono<List<String>> routesMono;

        if (GatewayType.TRAEFIK == gatewayType) {
            routesMono = extractTraefik(client, target);
        } else if (GatewayType.SPRING_CLOUD_GATEWAY == gatewayType) {
            routesMono = extractSpringCloudGateway(client, target);
        } else if (GatewayType.KONG == gatewayType) {
            routesMono = extractKong(client, target);
        } else if (GatewayType.K8S == gatewayType) {
            routesMono = extractKubernetes(client, target, config.k8sToken());
        } else if (GatewayType.HAPROXY == gatewayType) {
            routesMono = extractHaproxy(client, target);
        } else {
            // Auto detect
            routesMono = extractTraefik(client, target)
                    .onErrorResume(e -> extractSpringCloudGateway(client, target))
                    .onErrorResume(e -> extractKong(client, target))
                    .onErrorResume(e -> extractHaproxy(client, target))
                    .onErrorResume(e -> {
                        log.error("Failed to auto-detect gateway at {}", target);
                        return Mono.just(new ArrayList<>());
                    });
        }

        return routesMono.flatMap(prefixes -> {
            log.info("Extracted {} route prefixes from Gateway. Starting Fuzzing on {}...", prefixes.size(), finalAppUrl);
            
            // Format prefixes
            Set<String> fullUrlsToFuzz = new HashSet<>();
            for (String prefix : prefixes) {
                // remove wildcards like /** or /*
                String cleanPrefix = prefix.replaceAll("/\\*.*$", "");
                if (!cleanPrefix.startsWith("/")) {
                    cleanPrefix = "/" + cleanPrefix;
                }
                fullUrlsToFuzz.add(finalAppUrl + cleanPrefix);
            }

            if (fullUrlsToFuzz.isEmpty()) {
                fullUrlsToFuzz.add(finalAppUrl);
            }

            return Flux.fromIterable(fullUrlsToFuzz)
                    .flatMap(url -> blackboxDiscoverer.discover(url, overrideHost, config))
                    .flatMapIterable(ops -> ops)
                    .collectList()
                    .map(allOps -> {
                        // Deduplicate
                        Set<String> seen = new HashSet<>();
                        List<Operation> unique = new ArrayList<>();
                        for (Operation op : allOps) {
                            if (seen.add(op.url() + op.method())) {
                                unique.add(op);
                            }
                        }
                        log.info("Gateway Discovery complete. Found {} valid endpoints.", unique.size());
                        return unique;
                    });
        });
    }

    private Mono<List<String>> extractTraefik(WebClient client, String target) {
        String url = target.endsWith("/") ? target + "api/http/routers" : target + "/api/http/routers";
        return client.get().uri(url)
                .retrieve()
                .bodyToFlux(JsonNode.class)
                .map(node -> {
                    String rule = node.path("rule").asText("");
                    return extractPathFromTraefikRule(rule);
                })
                .filter(s -> !s.isEmpty())
                .collectList();
    }

    private String extractPathFromTraefikRule(String rule) {
        // E.g. PathPrefix(`/api/v1`) or Path(`/auth`)
        if (rule.contains("PathPrefix(`")) {
            int start = rule.indexOf("PathPrefix(`") + 12;
            int end = rule.indexOf("`)", start);
            if (end > start) return rule.substring(start, end);
        } else if (rule.contains("Path(`")) {
            int start = rule.indexOf("Path(`") + 6;
            int end = rule.indexOf("`)", start);
            if (end > start) return rule.substring(start, end);
        }
        return "";
    }

    private Mono<List<String>> extractSpringCloudGateway(WebClient client, String target) {
        String url = target.endsWith("/") ? target + "actuator/gateway/routes" : target + "/actuator/gateway/routes";
        return client.get().uri(url)
                .retrieve()
                .bodyToFlux(JsonNode.class)
                .map(node -> node.path("predicate").asText(""))
                .map(predicate -> {
                    // E.g. Paths: [/api/**], match trailing slash: true
                    if (predicate.contains("Paths: [")) {
                        int start = predicate.indexOf("Paths: [") + 8;
                        int end = predicate.indexOf("]", start);
                        if (end > start) return predicate.substring(start, end);
                    }
                    return "";
                })
                .filter(s -> !s.isEmpty())
                .collectList();
    }

    private Mono<List<String>> extractKong(WebClient client, String target) {
        String url = target.endsWith("/") ? target + "routes" : target + "/routes";
        return client.get().uri(url)
                .retrieve()
                .bodyToMono(JsonNode.class)
                .map(root -> {
                    List<String> paths = new ArrayList<>();
                    JsonNode data = root.path("data");
                    if (data.isArray()) {
                        for (JsonNode route : data) {
                            JsonNode pNode = route.path("paths");
                            if (pNode.isArray() && pNode.size() > 0) {
                                paths.add(pNode.get(0).asText());
                            }
                        }
                    }
                    return paths;
                });
    }

    private Mono<List<String>> extractKubernetes(WebClient client, String target, String token) {
        if (token == null || token.isEmpty()) {
            token = System.getenv("K8S_TOKEN");
        }
        if (token == null) {
            return Mono.error(new IllegalArgumentException("K8S_TOKEN is required for Kubernetes Ingress discovery"));
        }

        String url = target.endsWith("/") ? target + "apis/networking.k8s.io/v1/ingresses" : target + "/apis/networking.k8s.io/v1/ingresses";
        
        return client.get().uri(url)
                .header("Authorization", "Bearer " + token)
                .retrieve()
                .bodyToMono(JsonNode.class)
                .map(root -> {
                    List<String> paths = new ArrayList<>();
                    JsonNode items = root.path("items");
                    if (items.isArray()) {
                        for (JsonNode item : items) {
                            JsonNode rules = item.path("spec").path("rules");
                            if (rules.isArray()) {
                                for (JsonNode rule : rules) {
                                    JsonNode httpPaths = rule.path("http").path("paths");
                                    if (httpPaths.isArray()) {
                                        for (JsonNode pathDef : httpPaths) {
                                            paths.add(pathDef.path("path").asText(""));
                                        }
                                    }
                                }
                            }
                        }
                    }
                    return paths;
                });
    }

    private Mono<List<String>> extractHaproxy(WebClient client, String target) {
        // Querying HAProxy Data Plane API for ACLs (requires Data Plane API to be exposed)
        // Note: For full accuracy, one would query /v2/services/haproxy/configuration/frontends first,
        // then fetch ACLs for each frontend. This is a simplified fetch assuming an endpoint provides all ACLs
        // or a custom wrapper script exposing them.
        String url = target.endsWith("/") ? target + "v2/services/haproxy/configuration/acls" : target + "/v2/services/haproxy/configuration/acls";
        
        return client.get().uri(url)
                .retrieve()
                .bodyToMono(JsonNode.class)
                .map(root -> {
                    List<String> paths = new ArrayList<>();
                    JsonNode data = root.path("data");
                    if (data.isArray()) {
                        for (JsonNode acl : data) {
                            String criterion = acl.path("criterion").asText("");
                            if (criterion.startsWith("path_beg") || criterion.startsWith("path") || criterion.startsWith("url_beg")) {
                                String value = acl.path("value").asText("");
                                if (!value.isEmpty()) {
                                    paths.add(value);
                                }
                            }
                        }
                    }
                    return paths;
                });
    }
}

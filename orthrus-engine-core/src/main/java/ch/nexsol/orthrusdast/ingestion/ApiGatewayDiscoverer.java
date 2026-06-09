/*
 * Copyright 2014-2024 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package ch.nexsol.orthrusdast.ingestion;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import com.fasterxml.jackson.databind.JsonNode;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import ch.nexsol.orthrusdast.model.GatewayType;
import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.ScanConfiguration;

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
	public Mono<List<Operation>> discover(String target, ScanConfiguration config) {
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
		}
		else if (GatewayType.SPRING_CLOUD_GATEWAY == gatewayType) {
			routesMono = extractSpringCloudGateway(client, target);
		}
		else if (GatewayType.KONG == gatewayType) {
			routesMono = extractKong(client, target);
		}
		else if (GatewayType.K8S == gatewayType) {
			routesMono = extractKubernetes(client, target, config.k8sToken());
		}
		else if (GatewayType.HAPROXY == gatewayType) {
			routesMono = extractHaproxy(client, target);
		}
		else {
			// Auto detect
			routesMono = extractTraefik(client, target).onErrorResume((e) -> extractSpringCloudGateway(client, target))
				.onErrorResume((e) -> extractKong(client, target))
				.onErrorResume((e) -> extractHaproxy(client, target))
				.onErrorResume((e) -> {
					log.error("Failed to auto-detect gateway at {}", target);
					return Mono.just(new ArrayList<>());
				});
		}

		return routesMono.flatMap((prefixes) -> {
			log.info("Extracted {} route prefixes from Gateway. Starting Fuzzing on {}...", prefixes.size(),
					finalAppUrl);

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
				.flatMap((url) -> blackboxDiscoverer.discover(url, config))
				.flatMapIterable((ops) -> ops)
				.collectList()
				.map((allOps) -> {
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
		return client.get().uri(url).retrieve().bodyToFlux(java.util.Map.class).map((node) -> {
			String rule = (String) node.get("rule");
			return (rule != null) ? extractPathFromTraefikRule(rule) : "";
		}).filter((s) -> !s.isEmpty()).collectList();
	}

	private String extractPathFromTraefikRule(String rule) {
		// E.g. PathPrefix(`/api/v1`) or Path(`/auth`)
		if (rule.contains("PathPrefix(`")) {
			int start = rule.indexOf("PathPrefix(`") + 12;
			int end = rule.indexOf("`)", start);
			if (end > start) {
				return rule.substring(start, end);
			}
		}
		else if (rule.contains("Path(`")) {
			int start = rule.indexOf("Path(`") + 6;
			int end = rule.indexOf("`)", start);
			if (end > start) {
				return rule.substring(start, end);
			}
		}
		return "";
	}

	private Mono<List<String>> extractSpringCloudGateway(WebClient client, String target) {
		String url = target.endsWith("/") ? target + "actuator/gateway/routes" : target + "/actuator/gateway/routes";
		return client.get().uri(url).retrieve().bodyToFlux(java.util.Map.class).map((node) -> {
			Object predicateObj = node.get("predicate");
			return (predicateObj != null) ? predicateObj.toString() : "";
		}).map((predicate) -> {
			// E.g. Paths: [/api/**], match trailing slash: true
			if (predicate.contains("Paths: [")) {
				int start = predicate.indexOf("Paths: [") + 8;
				int end = predicate.indexOf("]", start);
				if (end > start) {
					return predicate.substring(start, end);
				}
			}
			return "";
		}).filter((s) -> !s.isEmpty()).collectList();
	}

	private Mono<List<String>> extractKong(WebClient client, String target) {
		String url = target.endsWith("/") ? target + "routes" : target + "/routes";
		return client.get().uri(url).retrieve().bodyToMono(java.util.Map.class).map((root) -> {
			List<String> paths = new ArrayList<>();
			Object dataObj = root.get("data");
			if (dataObj instanceof List) {
				for (Object routeObj : (List<?>) dataObj) {
					if (routeObj instanceof java.util.Map) {
						Object pObj = ((java.util.Map<?, ?>) routeObj).get("paths");
						if (pObj instanceof List && !((List<?>) pObj).isEmpty()) {
							paths.add(((List<?>) pObj).get(0).toString());
						}
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

		String url = target.endsWith("/") ? target + "apis/networking.k8s.io/v1/ingresses"
				: target + "/apis/networking.k8s.io/v1/ingresses";

		return client.get()
			.uri(url)
			.header("Authorization", "Bearer " + token)
			.retrieve()
			.bodyToMono(java.util.Map.class)
			.map((root) -> {
				List<String> paths = new ArrayList<>();
				Object itemsObj = root.get("items");
				if (itemsObj instanceof List) {
					for (Object itemObj : (List<?>) itemsObj) {
						if (itemObj instanceof java.util.Map) {
							Object specObj = ((java.util.Map<?, ?>) itemObj).get("spec");
							if (specObj instanceof java.util.Map) {
								Object rulesObj = ((java.util.Map<?, ?>) specObj).get("rules");
								if (rulesObj instanceof List) {
									for (Object ruleObj : (List<?>) rulesObj) {
										if (ruleObj instanceof java.util.Map) {
											Object httpObj = ((java.util.Map<?, ?>) ruleObj).get("http");
											if (httpObj instanceof java.util.Map) {
												Object pathsObj = ((java.util.Map<?, ?>) httpObj).get("paths");
												if (pathsObj instanceof List) {
													for (Object pathItemObj : (List<?>) pathsObj) {
														if (pathItemObj instanceof java.util.Map) {
															Object p = ((java.util.Map<?, ?>) pathItemObj).get("path");
															if (p != null) {
																paths.add(p.toString());
															}
														}
													}
												}
											}
										}
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
		// Querying HAProxy Data Plane API for ACLs (requires Data Plane API to be
		// exposed)
		// Note: For full accuracy, one would query
		// /v2/services/haproxy/configuration/frontends first,
		// then fetch ACLs for each frontend. This is a simplified fetch assuming an
		// endpoint provides all ACLs
		// or a custom wrapper script exposing them.
		String url = target.endsWith("/") ? target + "v2/services/haproxy/configuration/acls"
				: target + "/v2/services/haproxy/configuration/acls";

		return client.get().uri(url).retrieve().bodyToMono(JsonNode.class).map((root) -> {
			List<String> paths = new ArrayList<>();
			JsonNode data = root.path("data");
			if (data.isArray()) {
				for (JsonNode acl : data) {
					String criterion = acl.path("criterion").asText("");
					if (criterion.startsWith("path_beg") || criterion.startsWith("path")
							|| criterion.startsWith("url_beg")) {
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

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

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import ch.nexsol.orthrusdast.config.OrthrusProperties;
import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.ScanConfiguration;
import ch.nexsol.orthrusdast.model.SecurityScheme;

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
	public Mono<List<Operation>> discover(String target, ScanConfiguration config) {
		SecurityScheme authScheme = (config != null) ? config.authScheme() : null;
		log.info("Starting Blackbox discovery on {}", target);

		return extractHost(target).flatMap((targetHost) -> {
			Set<String> visitedUrls = ConcurrentHashMap.newKeySet();
			List<Operation> discoveredEndpoints = Collections.synchronizedList(new ArrayList<>());

			return crawl(target, targetHost, 0, visitedUrls, discoveredEndpoints, authScheme).then(Mono.defer(() -> {
				log.info("Discovered {} endpoints via HTML crawling", discoveredEndpoints.size());
				return Mono.just(discoveredEndpoints);
			})).flatMap((crawledEndpoints) -> {
				log.info("Starting API Dictionary Fuzzing on {}", target);
				Mono<List<String>> dictionaryMono = Mono.fromCallable(() -> {
					List<String> list = new ArrayList<>();
					try (BufferedReader br = new BufferedReader(
							new InputStreamReader(new ClassPathResource("api-wordlist.txt").getInputStream()))) {
						String line;
						while ((line = br.readLine()) != null) {
							if (!line.trim().isEmpty()) {
								list.add(line.trim());
							}
						}
					}
					return list;
				}).onErrorResume((ex) -> {
					log.warn("Could not load api-wordlist.txt: {}", ex.getMessage());
					return Mono.just(new ArrayList<>());
				});

				return dictionaryMono.flatMap((dictionary) -> {
					if (dictionary.isEmpty()) {
						return Mono.just(crawledEndpoints);
					}

					String baseUrl = target.endsWith("/") ? target : target + "/";
					WebClient client = WebClient.builder().baseUrl(baseUrl).build();

					return Flux.fromIterable(dictionary).flatMap((path) -> {
						String cleanPath = path.startsWith("/") ? path.substring(1) : path;
						return client.head().uri(cleanPath).exchangeToMono((response) -> {
							if (isValidResponse(response.statusCode().value())) {
								return Mono
									.just(Operation.simple(baseUrl + cleanPath, HttpMethod.GET).withAuth(authScheme));
							}
							return Mono.<Operation>empty();
						})
							.onErrorResume((e) -> Mono.empty())
							.switchIfEmpty(client.get().uri(cleanPath).exchangeToMono((response) -> {
								if (isValidResponse(response.statusCode().value())) {
									return Mono.just(
											Operation.simple(baseUrl + cleanPath, HttpMethod.GET).withAuth(authScheme));
								}
								return Mono.<Operation>empty();
							}).onErrorResume((e) -> Mono.empty()))
							.switchIfEmpty(client.post().uri(cleanPath).exchangeToMono((response) -> {
								if (isValidResponse(response.statusCode().value())) {
									return Mono.just(Operation.simple(baseUrl + cleanPath, HttpMethod.POST)
										.withAuth(authScheme));
								}
								return Mono.<Operation>empty();
							}).onErrorResume((e) -> Mono.empty()));
					}, 20) // concurrency of 20
						.collectList()
						.map((fuzzedEndpoints) -> {
							Set<String> urls = new HashSet<>();
							List<Operation> combined = new ArrayList<>();
							for (Operation op : crawledEndpoints) {
								if (urls.add(op.url())) {
									combined.add(op);
								}
							}
							for (Operation op : fuzzedEndpoints) {
								if (urls.add(op.url())) {
									combined.add(op);
								}
							}
							log.info("Discovered {} total endpoints after fuzzing", combined.size());
							return combined;
						});
				});
			});
		});
	}

	private Mono<String> extractHost(String url) {
		return Mono.fromCallable(() -> new URI(url).getHost()).onErrorReturn("");
	}

	private boolean isValidResponse(int statusCode) {
		// Accept 2xx, 3xx, 400 Bad Request, 401 Unauthorized, 403 Forbidden, 415
		// Unsupported Media Type, and 5xx (Server Errors)
		return (statusCode >= 200 && statusCode < 400) || (statusCode >= 500 && statusCode < 600) || statusCode == 400
				|| statusCode == 401 || statusCode == 403 || statusCode == 415;
	}

	private Mono<Void> crawl(String url, String targetHost, int depth, Set<String> visitedUrls,
			List<Operation> discoveredEndpoints, SecurityScheme authScheme) {
		int maxDepth = properties.getDiscovery().getBlackboxMaxDepth();
		if (depth > maxDepth) {
			return Mono.empty();
		}
		if (visitedUrls.contains(url)) {
			return Mono.empty();
		}

		return Mono.fromCallable(() -> {
			URI uri = new URI(url);
			return targetHost.equals(uri.getHost());
		}).onErrorReturn(false).flatMap((isValid) -> {
			if (!isValid) {
				return Mono.empty();
			}

			visitedUrls.add(url);
			return Mono.fromCallable(() -> {
				org.jsoup.nodes.Document doc = org.jsoup.Jsoup.connect(url).timeout(5000).ignoreContentType(true).get();
				return doc;
			}).subscribeOn(Schedulers.boundedElastic()).flatMap((doc) -> {
				discoveredEndpoints.add(Operation.simple(url, HttpMethod.GET).withAuth(authScheme));

				List<Mono<Void>> recursiveCalls = new ArrayList<>();

				Elements links = doc.select("a[href]");
				for (Element link : links) {
					String nextUrl = link.absUrl("href");
					if (nextUrl != null && !nextUrl.isEmpty()) {
						recursiveCalls
							.add(crawl(nextUrl, targetHost, depth + 1, visitedUrls, discoveredEndpoints, authScheme));
					}
				}

				Elements forms = doc.select("form");
				for (Element form : forms) {
					String actionUrl = form.absUrl("action");
					String method = form.attr("method").toUpperCase();
					if (method.isEmpty()) {
						method = "GET";
					}
					if (actionUrl != null && !actionUrl.isEmpty()) {
						discoveredEndpoints
							.add(Operation.simple(actionUrl, HttpMethod.valueOf(method)).withAuth(authScheme));
						if ("GET".equals(method)) {
							recursiveCalls.add(crawl(actionUrl, targetHost, depth + 1, visitedUrls, discoveredEndpoints,
									authScheme));
						}
					}
				}

				return Flux.concat(recursiveCalls).then();
			}).onErrorResume((ex) -> {
				log.warn("Failed to fetch or parse URL {}: {}", url, ex.getMessage());
				return Mono.empty();
			});
		});
	}

}

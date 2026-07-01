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

package ch.nexsol.orthrusdast.web;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import ch.nexsol.orthrusdast.engine.ScanResultService;
import ch.nexsol.orthrusdast.engine.StatisticsService;

/**
 * General pages: home, login, user manual and statistics. Scans, plans, system
 * administration and report downloads live in their dedicated controllers.
 */
@Controller
public class FrontendController {

	private final ScanResultService scanResultService;

	private final StatisticsService statisticsService;

	private final ObjectProvider<ReactiveClientRegistrationRepository> clientRegistrations;

	public FrontendController(ScanResultService scanResultService, StatisticsService statisticsService,
			ObjectProvider<ReactiveClientRegistrationRepository> clientRegistrations) {
		this.scanResultService = scanResultService;
		this.statisticsService = statisticsService;
		this.clientRegistrations = clientRegistrations;
	}

	@GetMapping("/login")
	public Mono<String> login(ServerWebExchange exchange, Model model) {
		model.addAttribute("oauth2Enabled", clientRegistrations.getIfAvailable() != null);
		if (exchange.getRequest().getQueryParams().containsKey("error")) {
			model.addAttribute("loginError", true);
		}
		if (exchange.getRequest().getQueryParams().containsKey("error_oauth2")) {
			model.addAttribute("loginErrorOauth2", true);
		}
		if (exchange.getRequest().getQueryParams().containsKey("logout")) {
			model.addAttribute("logoutMessage", true);
		}
		return Mono.just("login");
	}

	@GetMapping("/manual")
	public Mono<String> manual(Model model) {
		return Mono.just("manual");
	}

	@GetMapping("/stats")
	public Mono<String> stats(Model model) {
		return Mono.zip(statisticsService.getEvolutionByTargetAndEndpoint(), statisticsService.getGlobalStatistics())
			.map((tuple) -> {
				model.addAttribute("endpointStats", tuple.getT1());
				model.addAttribute("globalStats", tuple.getT2());
				return "stats";
			});
	}

	@GetMapping("/")
	public Mono<String> index(Model model) {
		Map<String, String> discovererDescriptions = new LinkedHashMap<>();
		discovererDescriptions.put("openapi",
				"Parses OpenAPI v2/v3 (Swagger) specifications to automatically discover all available endpoints, methods, parameters, and authentication schemes.");
		discovererDescriptions.put("graphql",
				"Introspects GraphQL schemas to discover available queries, mutations, and input types, enabling deep scanning of single-endpoint APIs.");
		discovererDescriptions.put("blackbox",
				"Performs brute-force and fuzzing techniques across a wide range of common API routes and parameter names to blindly discover undocumented endpoints.");
		discovererDescriptions.put("well-known",
				"Explores standard predictable paths (e.g., /.well-known/, /swagger-ui.html, /robots.txt) to uncover hidden API endpoints, administrative interfaces, or sensitive configuration files.");
		discovererDescriptions.put("curl",
				"Parses raw cURL commands to extract target URLs, HTTP methods, headers, and request payloads, allowing you to easily scan specific endpoints captured from your browser.");
		model.addAttribute("discoverers", discovererDescriptions);

		return scanResultService.findAll().collectList().map((history) -> {
			int totalScans = history.size();
			long totalVulns = history.stream().mapToLong((scan) -> scan.vulnerabilities().size()).sum();

			model.addAttribute("totalScans", totalScans);
			model.addAttribute("totalVulns", totalVulns);
			return "home";
		});
	}

}

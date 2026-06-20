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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.parameters.Parameter;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.parser.OpenAPIV3Parser;
import net.datafaker.Faker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.ScanConfiguration;
import ch.nexsol.orthrusdast.model.SecurityScheme;

@Component
public class OpenApiDiscoverer implements EndpointDiscoverer {

	private static final Logger log = LoggerFactory.getLogger(OpenApiDiscoverer.class);

	private final Faker faker = new Faker();

	@Override
	public String getId() {
		return "openapi";
	}

	@Override
	public Mono<List<Operation>> discover(String target, ScanConfiguration config) {
		SecurityScheme authScheme = (config != null) ? config.authScheme() : null;
		log.info("Parsing OpenAPI spec from: {}", target);

		// Parsing OpenAPI can be blocking, so we wrap it in Mono.fromCallable and
		// subscribe on bounded elastic
		return Mono.fromCallable(() -> parseSpec(target, config)).subscribeOn(Schedulers.boundedElastic());
	}

	private List<Operation> parseSpec(String specUrl, ScanConfiguration config) {
		SecurityScheme authScheme = (config != null) ? config.authScheme() : null;
		List<Operation> endpoints = new ArrayList<>();

		OpenAPI openAPI = new OpenAPIV3Parser().read(specUrl);
		if (openAPI == null) {
			log.error("Failed to parse OpenAPI specification from {}", specUrl);
			throw new IllegalArgumentException("Failed to parse OpenAPI specification from " + specUrl
					+ ". Please ensure it is a valid OpenAPI v3 JSON/YAML file.");
		}

		String baseUrl = "";
		if (config != null && config.openapiOverrideHost() != null && !config.openapiOverrideHost().isEmpty()) {
			baseUrl = config.openapiOverrideHost();
		}
		else if (openAPI.getServers() != null && !openAPI.getServers().isEmpty()) {
			baseUrl = openAPI.getServers().get(0).getUrl();
		}

		// Strip trailing slash if present
		if (baseUrl.endsWith("/")) {
			baseUrl = baseUrl.substring(0, baseUrl.length() - 1);
		}

		if (openAPI.getPaths() != null) {
			for (Map.Entry<String, PathItem> entry : openAPI.getPaths().entrySet()) {
				String path = entry.getKey();
				PathItem pathItem = entry.getValue();

				List<HttpMethod> supportedMethods = new ArrayList<>();
				if (pathItem.getGet() != null) {
					supportedMethods.add(HttpMethod.GET);
				}
				if (pathItem.getPost() != null) {
					supportedMethods.add(HttpMethod.POST);
				}
				if (pathItem.getPut() != null) {
					supportedMethods.add(HttpMethod.PUT);
				}
				if (pathItem.getDelete() != null) {
					supportedMethods.add(HttpMethod.DELETE);
				}
				if (pathItem.getPatch() != null) {
					supportedMethods.add(HttpMethod.PATCH);
				}
				if (pathItem.getOptions() != null) {
					supportedMethods.add(HttpMethod.OPTIONS);
				}

				if (pathItem.getGet() != null) {
					endpoints.add(buildOperation(baseUrl, path, HttpMethod.GET, pathItem.getGet(), openAPI, authScheme,
							supportedMethods));
				}
				if (pathItem.getPost() != null) {
					endpoints.add(buildOperation(baseUrl, path, HttpMethod.POST, pathItem.getPost(), openAPI,
							authScheme, supportedMethods));
				}
				if (pathItem.getPut() != null) {
					endpoints.add(buildOperation(baseUrl, path, HttpMethod.PUT, pathItem.getPut(), openAPI, authScheme,
							supportedMethods));
				}
				if (pathItem.getDelete() != null) {
					endpoints.add(buildOperation(baseUrl, path, HttpMethod.DELETE, pathItem.getDelete(), openAPI,
							authScheme, supportedMethods));
				}
				if (pathItem.getPatch() != null) {
					endpoints.add(buildOperation(baseUrl, path, HttpMethod.PATCH, pathItem.getPatch(), openAPI,
							authScheme, supportedMethods));
				}
				if (pathItem.getOptions() != null) {
					endpoints.add(buildOperation(baseUrl, path, HttpMethod.OPTIONS, pathItem.getOptions(), openAPI,
							authScheme, supportedMethods));
				}
			}
		}

		log.info("Discovered {} endpoints from OpenAPI spec", endpoints.size());
		return endpoints;
	}

	private Operation buildOperation(String baseUrl, String path, HttpMethod method,
			io.swagger.v3.oas.models.Operation operation, OpenAPI openAPI, SecurityScheme authScheme,
			List<HttpMethod> supportedMethods) {
		Map<String, String> queryParams = new HashMap<>();
		Map<String, String> headers = new HashMap<>();
		String actualPath = path;

		if (operation.getParameters() != null) {
			for (Parameter param : operation.getParameters()) {
				if ("query".equals(param.getIn())) {
					queryParams.put(param.getName(), generateMockValue(param));
				}
				else if ("path".equals(param.getIn())) {
					actualPath = actualPath.replace("{" + param.getName() + "}", generateMockValue(param));
				}
				else if ("header".equals(param.getIn())) {
					headers.put(param.getName(), generateMockValue(param));
				}
			}
		}

		List<String> securityRequirements = new ArrayList<>();
		if (operation.getSecurity() != null) {
			for (SecurityRequirement req : operation.getSecurity()) {
				securityRequirements.addAll(req.keySet());
			}
		}
		else if (openAPI.getSecurity() != null) {
			for (SecurityRequirement req : openAPI.getSecurity()) {
				securityRequirements.addAll(req.keySet());
			}
		}

		String mockPayload = null;
		List<String> expectedContentTypes = new ArrayList<>();
		if (operation.getRequestBody() != null && operation.getRequestBody().getContent() != null) {
			expectedContentTypes.addAll(operation.getRequestBody().getContent().keySet());
			if (expectedContentTypes.contains("application/json")) {
				mockPayload = "{\"data\": \"" + faker.lorem().word() + "\"}";
				headers.put("Content-Type", "application/json");
			}
		}

		return new Operation(baseUrl + actualPath, method, headers, queryParams, mockPayload, securityRequirements,
				expectedContentTypes, authScheme, baseUrl + path, operation, supportedMethods);
	}

	private String generateMockValue(Parameter param) {
		if (param.getSchema() != null && param.getSchema().getType() != null) {
			return switch (param.getSchema().getType()) {
				case "integer", "number" -> String.valueOf(faker.number().numberBetween(1, 100));
				case "boolean" -> "true";
				default -> faker.lorem().word();
			};
		}
		return faker.lorem().word();
	}

}

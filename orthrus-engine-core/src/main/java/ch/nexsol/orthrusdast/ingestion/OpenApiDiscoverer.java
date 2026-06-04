package ch.nexsol.orthrusdast.ingestion;

import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.SecurityScheme;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.parameters.Parameter;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.parser.OpenAPIV3Parser;
import net.datafaker.Faker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import reactor.core.scheduler.Schedulers;

@Component
public class OpenApiDiscoverer implements EndpointDiscoverer {

    private static final Logger log = LoggerFactory.getLogger(OpenApiDiscoverer.class);
    private final Faker faker = new Faker();

    @Override
    public String getId() {
        return "openapi";
    }

    @Override
    public Mono<List<Operation>> discover(String target, String overrideHost, ch.nexsol.orthrusdast.model.ScanConfiguration config) {
        ch.nexsol.orthrusdast.model.SecurityScheme authScheme = config != null ? config.authScheme() : null;
        log.info("Parsing OpenAPI spec from: {}", target);
        
        // Parsing OpenAPI can be blocking, so we wrap it in Mono.fromCallable and subscribe on bounded elastic
        return Mono.fromCallable(() -> parseSpec(target, overrideHost, authScheme))
                   .subscribeOn(Schedulers.boundedElastic());
    }
    
    private List<Operation> parseSpec(String specUrl, String overrideHost, SecurityScheme authScheme) {
        List<Operation> endpoints = new ArrayList<>();
        
        OpenAPI openAPI = new OpenAPIV3Parser().read(specUrl);
        if (openAPI == null) {
            log.error("Failed to parse OpenAPI specification from {}", specUrl);
            throw new IllegalArgumentException("Failed to parse OpenAPI specification from " + specUrl + ". Please ensure it is a valid OpenAPI v3 JSON/YAML file.");
        }

        String baseUrl = "";
        if (overrideHost != null && !overrideHost.isEmpty()) {
            baseUrl = overrideHost;
        } else if (openAPI.getServers() != null && !openAPI.getServers().isEmpty()) {
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

                if (pathItem.getGet() != null) endpoints.add(buildOperation(baseUrl, path, "GET", pathItem.getGet(), openAPI, authScheme));
                if (pathItem.getPost() != null) endpoints.add(buildOperation(baseUrl, path, "POST", pathItem.getPost(), openAPI, authScheme));
                if (pathItem.getPut() != null) endpoints.add(buildOperation(baseUrl, path, "PUT", pathItem.getPut(), openAPI, authScheme));
                if (pathItem.getDelete() != null) endpoints.add(buildOperation(baseUrl, path, "DELETE", pathItem.getDelete(), openAPI, authScheme));
                if (pathItem.getPatch() != null) endpoints.add(buildOperation(baseUrl, path, "PATCH", pathItem.getPatch(), openAPI, authScheme));
                if (pathItem.getOptions() != null) endpoints.add(buildOperation(baseUrl, path, "OPTIONS", pathItem.getOptions(), openAPI, authScheme));
            }
        }
        
        log.info("Discovered {} endpoints from OpenAPI spec", endpoints.size());
        return endpoints;
    }

    private Operation buildOperation(String baseUrl, String path, String method, io.swagger.v3.oas.models.Operation operation, OpenAPI openAPI, SecurityScheme authScheme) {
        Map<String, String> queryParams = new HashMap<>();
        Map<String, String> headers = new HashMap<>();
        String actualPath = path;

        if (operation.getParameters() != null) {
            for (Parameter param : operation.getParameters()) {
                if ("query".equals(param.getIn())) {
                    queryParams.put(param.getName(), generateMockValue(param));
                } else if ("path".equals(param.getIn())) {
                    actualPath = actualPath.replace("{" + param.getName() + "}", generateMockValue(param));
                } else if ("header".equals(param.getIn())) {
                    headers.put(param.getName(), generateMockValue(param));
                }
            }
        }

        List<String> securityRequirements = new ArrayList<>();
        if (operation.getSecurity() != null) {
            for (SecurityRequirement req : operation.getSecurity()) {
                securityRequirements.addAll(req.keySet());
            }
        } else if (openAPI.getSecurity() != null) {
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

        return new Operation(
                baseUrl + actualPath,
                method,
                headers,
                queryParams,
                mockPayload,
                securityRequirements,
                expectedContentTypes,
                authScheme,
                baseUrl + path,
                operation
        );
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

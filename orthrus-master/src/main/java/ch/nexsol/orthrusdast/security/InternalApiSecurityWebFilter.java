package ch.nexsol.orthrusdast.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import ch.nexsol.orthrusdast.config.OrthrusProperties;

@Component
public class InternalApiSecurityWebFilter implements WebFilter {

	private static final Logger log = LoggerFactory.getLogger(InternalApiSecurityWebFilter.class);

	private static final String HEADER_NAME = "X-Orthrus-Internal-Token";

	private final String expectedToken;

	public InternalApiSecurityWebFilter(OrthrusProperties properties) {
		this.expectedToken = properties.getMaster().getInternalToken();
	}

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
		String path = exchange.getRequest().getURI().getPath();

		if (path.startsWith("/api/internal/")) {
			String token = exchange.getRequest().getHeaders().getFirst(HEADER_NAME);

			if (token == null || !token.equals(expectedToken)) {
				log.warn("Unauthorized access attempt to internal API: {} (IP: {})", path,
						exchange.getRequest().getRemoteAddress());
				exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
				return exchange.getResponse().setComplete();
			}
		}

		return chain.filter(exchange);
	}

}

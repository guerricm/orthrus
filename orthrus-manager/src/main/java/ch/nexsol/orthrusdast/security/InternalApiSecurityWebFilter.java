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

package ch.nexsol.orthrusdast.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import ch.nexsol.orthrusdast.config.OrthrusProperties;

/**
 * Guards {@code /api/internal/**} with a shared secret. The Spring Security chain marks
 * those paths {@code permitAll()}, so this filter is their only protection and must run
 * first.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class InternalApiSecurityWebFilter implements WebFilter {

	private static final Logger log = LoggerFactory.getLogger(InternalApiSecurityWebFilter.class);

	private static final String HEADER_NAME = "X-Orthrus-Internal-Token";

	private static final String INTERNAL_PATH_PREFIX = "/api/internal/";

	private final byte[] expectedToken;

	public InternalApiSecurityWebFilter(OrthrusProperties properties) {
		String token = properties.getMaster().getInternalToken();
		this.expectedToken = (token != null) ? token.getBytes(StandardCharsets.UTF_8) : new byte[0];
	}

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
		String path = exchange.getRequest().getURI().getPath();

		if (path.startsWith(INTERNAL_PATH_PREFIX)) {
			String presented = exchange.getRequest().getHeaders().getFirst(HEADER_NAME);

			if (!matchesExpectedToken(presented)) {
				log.warn("Unauthorized access attempt to internal API: {} (IP: {})", path,
						exchange.getRequest().getRemoteAddress());
				exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
				return exchange.getResponse().setComplete();
			}
		}

		return chain.filter(exchange);
	}

	/**
	 * Compares in constant time so response latency does not leak how much of the token a
	 * caller guessed correctly.
	 * @param presented the token sent by the caller, may be null
	 * @return true when it matches the configured secret
	 */
	private boolean matchesExpectedToken(String presented) {
		if (presented == null || this.expectedToken.length == 0) {
			return false;
		}
		return MessageDigest.isEqual(presented.getBytes(StandardCharsets.UTF_8), this.expectedToken);
	}

}

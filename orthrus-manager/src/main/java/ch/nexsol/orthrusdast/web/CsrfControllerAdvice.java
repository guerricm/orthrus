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

import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Exposes the CSRF token as {@code ${_csrf}} in Thymeleaf models. Unlike Servlet MVC,
 * WebFlux does not inject the token into views automatically.
 */
@ControllerAdvice
public class CsrfControllerAdvice {

	@ModelAttribute("_csrf")
	public Mono<CsrfToken> csrfToken(ServerWebExchange exchange) {
		return exchange.getAttributeOrDefault(CsrfToken.class.getName(), Mono.empty());
	}

}

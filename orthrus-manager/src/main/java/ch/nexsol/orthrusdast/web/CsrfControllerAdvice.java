package ch.nexsol.orthrusdast.web;

import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Exposes the CSRF token as {@code ${_csrf}} in Thymeleaf models. Unlike Servlet
 * MVC, WebFlux does not inject the token into views automatically.
 */
@ControllerAdvice
public class CsrfControllerAdvice {

	@ModelAttribute("_csrf")
	public Mono<CsrfToken> csrfToken(ServerWebExchange exchange) {
		return exchange.getAttributeOrDefault(CsrfToken.class.getName(), Mono.empty());
	}

}

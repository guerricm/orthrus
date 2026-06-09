package ch.nexsol.orthrusdast.config;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

	@Value("${orthrus.security.admin.username:superadmin}")
	private String adminUsername;

	@Value("${orthrus.security.admin.password:superpassword}")
	private String adminPassword;

	@Bean
	public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http,
			ObjectProvider<ReactiveClientRegistrationRepository> clientRegistrations,
			ObjectProvider<ReactiveJwtDecoder> jwtDecoder) {

		http.authorizeExchange(exchanges -> exchanges
			// Public paths
			.pathMatchers("/css/**", "/js/**", "/images/**", "/webjars/**", "/favicon.ico", "/login**")
			.permitAll()
			// Internal API for slaves (Secured manually by InternalApiSecurityWebFilter)
			.pathMatchers("/api/internal/**")
			.permitAll()
			// System configuration requires ADMIN
			.pathMatchers("/system/**")
			.hasRole("ADMIN")
			// Everything else requires USER or ADMIN
			.anyExchange()
			.hasAnyRole("ADMIN", "USER"))
			.formLogin(form -> form.loginPage("/login"))
			.logout(logout -> logout.requiresLogout(ServerWebExchangeMatchers.pathMatchers("/logout")))
			.csrf(ServerHttpSecurity.CsrfSpec::disable);

		if (clientRegistrations.getIfAvailable() != null) {
			http.oauth2Login(oauth2 -> oauth2.loginPage("/login"));
		}

		if (jwtDecoder.getIfAvailable() != null) {
			http.oauth2ResourceServer(
					oauth2 -> oauth2.jwt(jwt -> jwt.jwtAuthenticationConverter(grantedAuthoritiesExtractor())));
		}

		return http.build();
	}

	@Bean
	public MapReactiveUserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
		UserDetails admin = User.builder()
			.username(adminUsername)
			.password(passwordEncoder.encode(adminPassword))
			.roles("ADMIN", "USER")
			.build();
		return new MapReactiveUserDetailsService(admin);
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}

	private Converter<Jwt, Mono<AbstractAuthenticationToken>> grantedAuthoritiesExtractor() {
		JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
		jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new CustomRoleConverter());
		return new ReactiveJwtAuthenticationConverterAdapter(jwtAuthenticationConverter);
	}

	static class CustomRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

		@Override
		public Collection<GrantedAuthority> convert(Jwt jwt) {
			Collection<GrantedAuthority> authorities = new ArrayList<>();

			// Check orthrus_roles claim
			List<String> orthrusRoles = jwt.getClaimAsStringList("orthrus_roles");
			if (orthrusRoles != null) {
				for (String role : orthrusRoles) {
					authorities.add(new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()));
				}
			}

			// Check resource_access.orthrus.roles claim
			Map<String, Object> resourceAccess = jwt.getClaimAsMap("resource_access");
			if (resourceAccess != null && resourceAccess.containsKey("orthrus")) {
				Object orthrusResource = resourceAccess.get("orthrus");
				if (orthrusResource instanceof Map) {
					Map<String, Object> orthrusMap = (Map<String, Object>) orthrusResource;
					Object rolesObj = orthrusMap.get("roles");
					if (rolesObj instanceof List) {
						List<String> roles = (List<String>) rolesObj;
						for (String role : roles) {
							authorities.add(new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()));
						}
					}
				}
			}

			return authorities;
		}

	}

}

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

package ch.nexsol.orthrusdast.scanner;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ch.nexsol.orthrusdast.http.ScanHttpClient;
import ch.nexsol.orthrusdast.model.CWEReference;
import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.RiskLevel;
import ch.nexsol.orthrusdast.model.Vulnerability;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;

/**
 * Scans authentication endpoints for susceptibility to brute force / weak passwords.
 * (CWE-307, CWE-521).
 */
@Component
public class AuthenticationBruteForceScanner implements SecurityScanner {

	private static final Logger log = LoggerFactory.getLogger(AuthenticationBruteForceScanner.class);

	private final ScanHttpClient httpClient;

	// List of extremely common weak passwords to test
	private final List<String> weakPasswords;

	// Regex to match JSON password fields like "password": "...", "pwd": "...", "pass":
	// "..."
	private static final Pattern PASSWORD_JSON_PATTERN = Pattern
		.compile("(\"(?:password|pwd|pass)\"\\s*:\\s*\")[^\"]*(\")", Pattern.CASE_INSENSITIVE);

	// Regex to match JSON username fields
	private static final Pattern USERNAME_JSON_PATTERN = Pattern
		.compile("(\"(?:username|user|email|login)\"\\s*:\\s*\")[^\"]*(\")", Pattern.CASE_INSENSITIVE);

	public AuthenticationBruteForceScanner(ScanHttpClient httpClient) {
		this.httpClient = httpClient;
		this.weakPasswords = loadPasswords();
	}

	private List<String> loadPasswords() {
		List<String> passwords = new ArrayList<>();
		try {
			ClassPathResource resource = new ClassPathResource("passwords.txt");
			if (resource.exists()) {
				try (BufferedReader reader = new BufferedReader(
						new InputStreamReader(resource.getInputStream(), StandardCharsets.UTF_8))) {
					String line;
					while ((line = reader.readLine()) != null) {
						String pw = line.trim();
						if (!pw.isEmpty()) {
							passwords.add(pw);
						}
					}
				}
				log.info("Loaded {} passwords for brute force scanning", passwords.size());
			}
			else {
				log.warn("passwords.txt not found on classpath, using minimal fallback list");
				passwords.addAll(List.of("123456", "password", "admin", "root", "qwerty"));
			}
		}
		catch (Exception e) {
			log.error("Failed to load passwords.txt", e);
			passwords.addAll(List.of("123456", "password", "admin", "root", "qwerty"));
		}
		return passwords;
	}

	@Override
	public String getId() {
		return "auth-bruteforce";
	}

	@Override
	public String getName() {
		return "Authentication Brute Force Scanner";
	}

	@Override
	public Flux<Vulnerability> scan(Operation operation) {
		return Flux.defer(() -> {
			String urlLower = operation.url().toLowerCase();
			boolean isAuthEndpoint = urlLower.contains("/login") || urlLower.contains("/auth")
					|| urlLower.contains("/token") || urlLower.contains("/signin");

			if (!isAuthEndpoint || !"POST".equalsIgnoreCase(operation.method()) || operation.body() == null) {
				return Flux.empty();
			}

			Matcher matcher = PASSWORD_JSON_PATTERN.matcher(operation.body());
			if (!matcher.find()) {
				// We couldn't identify a password field in the JSON body, or it's not
				// JSON
				return Flux.empty();
			}

			log.debug("Scanning for Brute Force / Weak Passwords on: {}", operation.url());

			Flux<Vulnerability> bruteForceVulns = Flux.fromIterable(weakPasswords).flatMap((weakPassword) -> {
				// Replace the original password with the weak password
				String modifiedBody = matcher.replaceAll("$1" + weakPassword + "$2");

				Operation testOp = new Operation(operation.url(), operation.method(), operation.headers(),
						operation.queryParams(), modifiedBody, operation.securityRequirements(),
						operation.expectedContentTypes(), operation.authScheme());

				return httpClient.send(testOp).flatMapMany((response) -> {
					// If we get a 200 OK with a weak password, it's a huge vulnerability
					if (response.statusCode().is2xxSuccessful()) {
						Vulnerability vuln = createVulnerabilityWithTrace("Weak Password Acceptance (Brute Force)",
								"The authentication endpoint accepted a very common weak password ('" + weakPassword
										+ "').",
								RiskLevel.CRITICAL, Vulnerability.Confidence.HIGH, operation, CWEReference.CWE_521,
								List.of("CAPEC-112"), 9.8,
								"Endpoint returned " + response.statusCode()
										+ " OK when authenticating with the weak password '" + weakPassword + "'.",
								"Implement strict password complexity requirements and rate limiting or account lockout mechanisms to prevent brute forcing.",
								testOp, response, "API Endpoint (Network)", "Unauthorized Access / Data Exposure");
						return Flux.just(vuln);
					}
					return Flux.empty();
				});
			});

			Flux<Vulnerability> enumerationVulns = Flux.empty();
			Matcher userMatcher = USERNAME_JSON_PATTERN.matcher(operation.body());
			if (userMatcher.find()) {
				String invalidUserBody = userMatcher.replaceAll("$1nonexistent_user_999999$2");
				String validUserBody = operation.body(); // Assuming original is valid or
															// at least exists

				Operation invalidUserOp = new Operation(operation.url(), operation.method(), operation.headers(),
						operation.queryParams(), invalidUserBody, operation.securityRequirements(),
						operation.expectedContentTypes(), operation.authScheme());

				Operation validUserOp = new Operation(operation.url(), operation.method(), operation.headers(),
						operation.queryParams(), validUserBody, operation.securityRequirements(),
						operation.expectedContentTypes(), operation.authScheme());

				enumerationVulns = httpClient.send(invalidUserOp)
					.zipWith(httpClient.send(validUserOp))
					.flatMapMany((tuple) -> {
						var invalidResp = tuple.getT1();
						var validResp = tuple.getT2();

						// Different status codes or completely different response body
						// lengths/content for auth failure
						if (!invalidResp.isSuccessful() && !validResp.isSuccessful()) {
							boolean diffStatus = !invalidResp.statusCode().equals(validResp.statusCode());
							boolean diffBody = !invalidResp.body().equals(validResp.body());

							if (diffStatus || diffBody) {
								Vulnerability vuln = createVulnerabilityWithTrace("Username Enumeration",
										"The authentication endpoint responds differently when a username exists versus when it does not. This allows an attacker to enumerate valid usernames.",
										RiskLevel.MEDIUM, Vulnerability.Confidence.MEDIUM, operation,
										CWEReference.CWE_200, List.of("CAPEC-114"), 5.3,
										"Response to invalid username was " + invalidResp.statusCode()
												+ " (Body length: " + invalidResp.body().length()
												+ "), but response to original username was " + validResp.statusCode()
												+ " (Body length: " + validResp.body().length() + ").",
										"Ensure authentication endpoints return a generic error message (e.g., 'Invalid username or password') and consistent HTTP status codes regardless of whether the username exists.",
										validUserOp, validResp, "API Endpoint (Network)",
										"Unauthorized Access / Data Exposure");
								return Flux.just(vuln);
							}
						}
						return Flux.empty();
					});
			}

			return Flux.concat(bruteForceVulns, enumerationVulns);
		});
	}

	private String truncate(String text) {
		if (text == null)
			return "null";
		return text.length() > 200 ? text.substring(0, 200) + "..." : text;
	}

}

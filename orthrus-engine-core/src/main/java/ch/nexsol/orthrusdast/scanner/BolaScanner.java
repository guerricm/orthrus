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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import ch.nexsol.orthrusdast.http.ScanHttpClient;
import ch.nexsol.orthrusdast.http.ScanHttpResponse;
import ch.nexsol.orthrusdast.model.CWEReference;
import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.RiskLevel;
import ch.nexsol.orthrusdast.model.Vulnerability;

/**
 * Scans for Broken Object Level Authorization (BOLA) / IDOR.
 *
 * <p>
 * Detection is differential: before flagging, the scanner fetches a control response for
 * a deliberately non-existent object of the same shape. A tampered ID is only reported
 * when its response is successful AND materially different from that control, which
 * removes the dominant false-positive source (endpoints that return a generic 200 page
 * regardless of the requested ID).
 * </p>
 */
@Component
public class BolaScanner implements SecurityScanner {

	private final ScanHttpClient httpClient;

	// Matches either a UUID or a numeric id as the last meaningful path segment.
	private static final Pattern ID_PATTERN = Pattern
		.compile("/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9]+)(/|$)");

	private static final Pattern NUMERIC = Pattern.compile("[0-9]+");

	// Length tolerance (percent) under which two response bodies are treated as the same
	// template rather than distinct objects.
	private static final int SAME_TEMPLATE_TOLERANCE_PCT = 5;

	public BolaScanner(ScanHttpClient httpClient) {
		this.httpClient = httpClient;
	}

	@Override
	public String getId() {
		return "bola";
	}

	@Override
	public String getName() {
		return "Broken Object Level Authorization (BOLA) Scanner";
	}

	@Override
	public ScannerFamily getFamily() {
		return ScannerFamily.AUTHENTICATION;
	}

	@Override
	public Flux<Vulnerability> scan(Operation operation) {
		return Flux.defer(() -> {
			Flux<Vulnerability> pathBola = testPathBola(operation);
			Flux<Vulnerability> queryBola = testQueryBola(operation);

			return Flux.concat(pathBola, queryBola);
		});
	}

	private Flux<Vulnerability> testPathBola(Operation operation) {
		Matcher matcher = ID_PATTERN.matcher(operation.url());
		if (!matcher.find()) {
			return Flux.empty();
		}

		String originalIdStr = matcher.group(1);
		boolean numeric = NUMERIC.matcher(originalIdStr).matches();

		// Control: a deliberately non-existent object of the same shape.
		String controlId = numeric ? buildNumericControl(originalIdStr) : UUID.randomUUID().toString();
		Operation controlOp = withPathId(operation, originalIdStr, controlId);

		return httpClient.send(controlOp).flatMapMany((control) -> {
			Mono<List<String>> testIdsMono;
			if (numeric) {
				testIdsMono = Mono.fromCallable(() -> {
					List<String> ids = new ArrayList<>();
					long id = Long.parseLong(originalIdStr);
					ids.add(String.valueOf(id + 1));
					ids.add(String.valueOf((id - 1 > 0) ? (id - 1) : (id + 2)));
					return ids;
				}).onErrorReturn(List.of(originalIdStr + "0"));
			}
			else {
				testIdsMono = Mono.just(List.of(UUID.randomUUID().toString()));
			}

			return testIdsMono.flatMapMany(Flux::fromIterable)
				.concatMap((testId) -> executeBolaCheck(withPathId(operation, originalIdStr, testId), operation,
						"URL path", originalIdStr, testId, control));
		});
	}

	private Flux<Vulnerability> testQueryBola(Operation operation) {
		if (operation.queryParams() == null || operation.queryParams().isEmpty()) {
			return Flux.empty();
		}

		return Flux.fromIterable(operation.queryParams().entrySet())
			.filter((entry) -> entry.getKey().toLowerCase().contains("id"))
			.concatMap((entry) -> {
				String paramName = entry.getKey();
				String originalValue = entry.getValue();

				// Control request: a non-existent id value of the same shape.
				boolean numeric = NUMERIC.matcher(originalValue).matches();
				String controlValue = numeric ? buildNumericControl(originalValue) : UUID.randomUUID().toString();
				Operation controlOp = withQueryParam(operation, paramName, controlValue);

				return httpClient.send(controlOp).flatMapMany((control) -> {
					// Test 1: array wrapping (?id[]=orig&id=fake) to probe HPP handling.
					Map<String, String> hppParams = new HashMap<>(operation.queryParams());
					hppParams.remove(paramName);
					hppParams.put(paramName + "[]", originalValue);
					hppParams.put(paramName, controlValue);
					Operation hppOp = new Operation(operation.url(), operation.method(), operation.headers(), hppParams,
							operation.body(), operation.securityRequirements(), operation.expectedContentTypes(),
							operation.authScheme());

					// Test 2: substitute a different id of the same shape.
					String substitute = numeric ? buildNumericControl(originalValue) : UUID.randomUUID().toString();
					Operation subOp = withQueryParam(operation, paramName, substitute);

					return Flux.concat(
							executeBolaCheck(hppOp, operation, "HPP/Array wrapping in Query param '" + paramName + "'",
									originalValue, controlValue, control),
							executeBolaCheck(subOp, operation, "ID substitution in Query param '" + paramName + "'",
									originalValue, substitute, control));
				});
			});
	}

	private Operation withPathId(Operation operation, String originalId, String newId) {
		String newUrl = operation.url()
			.replaceFirst("/" + Pattern.quote(originalId) + "(/|$)", "/" + Matcher.quoteReplacement(newId) + "$1");
		return new Operation(newUrl, operation.method(), operation.headers(), operation.queryParams(), operation.body(),
				operation.securityRequirements(), operation.expectedContentTypes(), operation.authScheme());
	}

	private Operation withQueryParam(Operation operation, String paramName, String value) {
		Map<String, String> params = new HashMap<>(operation.queryParams());
		params.put(paramName, value);
		return new Operation(operation.url(), operation.method(), operation.headers(), params, operation.body(),
				operation.securityRequirements(), operation.expectedContentTypes(), operation.authScheme());
	}

	/**
	 * Builds a numeric id that is almost certainly non-existent, used as a control to
	 * learn how the endpoint responds to an unknown object.
	 * @param sample the original id, used to mirror its order of magnitude
	 * @return a large, unlikely-to-exist numeric id
	 */
	private String buildNumericControl(String sample) {
		// Prefix with a high digit and pad to make collisions improbable.
		return "9" + sample + "87654321";
	}

	private Flux<Vulnerability> executeBolaCheck(Operation testOp, Operation originalOp, String location,
			String originalId, String testId, ScanHttpResponse control) {
		return httpClient.send(testOp).flatMapMany((response) -> {
			boolean substantiveSuccess = response.isSuccessful() && response.body() != null
					&& response.body().length() > 20 && !response.bodyContains("error")
					&& !response.bodyContains("not found") && !response.bodyContains("forbidden")
					&& !response.bodyContains("unauthorized");

			if (!substantiveSuccess) {
				return Flux.empty();
			}

			// Differential gate: if the tampered response is indistinguishable from the
			// non-existent control, the endpoint is not actually exposing a distinct
			// object, so this is not a finding.
			if (control != null && looksLikeSameResponse(response, control)) {
				return Flux.empty();
			}

			Vulnerability vuln = createVulnerabilityWithTrace("Potential Broken Object Level Authorization (BOLA)",
					"The endpoint returned a distinct, successful response when the resource ID was modified in "
							+ location + " from " + originalId + " to " + testId
							+ ", and that response differed from the control fetched for a non-existent object. "
							+ "Verify the authenticated user is authorized to access this specific object.",
					RiskLevel.MEDIUM, Vulnerability.Confidence.MEDIUM, originalOp, CWEReference.CWE_639,
					List.of("CAPEC-17"), 7.5,
					"Response status " + response.statusCode() + " with object-specific data when accessing ID "
							+ testId + " (control for a non-existent object returned a different response).",
					"Implement strict authorization checks at the object level. Verify the user requesting the data owns or has roles to access it. Validate data types (e.g. UUIDs vs Ints).",
					testOp, response, "API Endpoint (Network)", "Unauthorized Access / Data Exposure");
			return Flux.just(vuln);
		});
	}

	/**
	 * Heuristic comparison: two responses are considered the same template (not distinct
	 * objects) when they share the same status code and their digit-normalized bodies are
	 * equal or within a small length tolerance. Normalizing digits avoids treating two
	 * generic pages that only differ by the echoed id as distinct.
	 * @param a the first response
	 * @param b the second response
	 * @return true if the two responses look like the same template
	 */
	private boolean looksLikeSameResponse(ScanHttpResponse a, ScanHttpResponse b) {
		if (b.body() == null) {
			return false;
		}
		if (a.statusCode().value() != b.statusCode().value()) {
			return false;
		}
		String na = normalize(a.body());
		String nb = normalize(b.body());
		if (na.equals(nb)) {
			return true;
		}
		int max = Math.max(na.length(), nb.length());
		if (max == 0) {
			return true;
		}
		return Math.abs(na.length() - nb.length()) * 100 / max <= SAME_TEMPLATE_TOLERANCE_PCT;
	}

	private String normalize(String body) {
		return body.replaceAll("[0-9]+", "#").replaceAll("\\s+", " ").trim();
	}

}

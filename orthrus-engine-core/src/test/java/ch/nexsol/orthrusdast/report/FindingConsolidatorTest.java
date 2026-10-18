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

package ch.nexsol.orthrusdast.report;

import java.util.List;

import org.junit.jupiter.api.Test;

import ch.nexsol.orthrus.protocol.node.RiskLevel;
import ch.nexsol.orthrus.protocol.node.Vulnerability;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A misconfiguration of the whole host (a missing header, the server banner, the CORS
 * policy) is one finding, not one per endpoint; endpoint-specific findings are left
 * alone.
 */
class FindingConsolidatorTest {

	private static final String HOST = "https://api.test";

	@Test
	void aHostWideFindingRepeatedOnEveryEndpointBecomesOneListingTheEndpoints() {
		List<Vulnerability> findings = List.of(
				finding("security-headers", "Missing Security Header: HSTS", RiskLevel.LOW, "GET", HOST + "/pet/1"),
				finding("security-headers", "Missing Security Header: HSTS", RiskLevel.LOW, "POST", HOST + "/pet"),
				finding("security-headers", "Missing Security Header: HSTS", RiskLevel.LOW, "GET",
						HOST + "/user/{username}"));

		List<Vulnerability> consolidated = FindingConsolidator.consolidate(findings);

		assertThat(consolidated).singleElement().satisfies((vuln) -> {
			assertThat(vuln.name()).isEqualTo("Missing Security Header: HSTS");
			assertThat(vuln.description()).contains("3 endpoints")
				.contains("GET " + HOST + "/pet/1")
				.contains("POST " + HOST + "/pet")
				.contains("GET " + HOST + "/user/{username}");
		});
	}

	@Test
	void theSameHeaderMissingOnTwoHostsStaysTwoFindings() {
		List<Vulnerability> findings = List.of(
				finding("security-headers", "Missing Security Header: HSTS", RiskLevel.LOW, "GET", HOST + "/a"),
				finding("security-headers", "Missing Security Header: HSTS", RiskLevel.LOW, "GET",
						"https://other.test/a"));

		assertThat(FindingConsolidator.consolidate(findings)).hasSize(2);
	}

	@Test
	void endpointSpecificFindingsAreNeverMerged() {
		List<Vulnerability> findings = List.of(
				finding("sqli", "SQL Injection", RiskLevel.CRITICAL, "GET", HOST + "/pet/findByStatus"),
				finding("sqli", "SQL Injection", RiskLevel.CRITICAL, "GET", HOST + "/user/login"));

		assertThat(FindingConsolidator.consolidate(findings)).hasSize(2);
	}

	@Test
	void aiAgentsReportingTheSameCorsPolicyInTheirOwnWordsBecomeOneFindingAtTheHighestSeverity() {
		List<Vulnerability> findings = List.of(
				finding("ai-configuration", "Permissive CORS (Access-Control-Allow-Origin: *)", RiskLevel.MEDIUM,
						"POST", HOST + "/pet"),
				finding("ai-configuration", "Permissive CORS with Sensitive Authorization Headers", RiskLevel.HIGH,
						"GET", HOST + "/pet/findByTags"),
				finding("ai-logic", "Overly permissive cors on write endpoint", RiskLevel.LOW, "PUT", HOST + "/pet"),
				finding("ai-xss", "Reflected XSS via unencoded petId", RiskLevel.MEDIUM, "GET", HOST + "/pet/{petId}"));

		List<Vulnerability> consolidated = FindingConsolidator.consolidate(findings);

		assertThat(consolidated).hasSize(2);
		assertThat(consolidated).filteredOn((vuln) -> vuln.name().toLowerCase().contains("cors"))
			.singleElement()
			.satisfies((vuln) -> {
				assertThat(vuln.riskLevel()).isEqualTo(RiskLevel.HIGH);
				assertThat(vuln.description()).contains("3 endpoints");
			});
	}

	@Test
	void aTitleMentioningSeveralTopicsAlwaysJoinsTheSameGroup() {
		List<Vulnerability> findings = List.of(
				finding("ai-configuration", "Missing X-Content-Type-Options and CSP Headers with Permissive CORS",
						RiskLevel.LOW, "POST", HOST + "/pet"),
				finding("ai-configuration", "Permissive CORS (Access-Control-Allow-Origin: *)", RiskLevel.MEDIUM, "GET",
						HOST + "/pet/findByStatus"));

		assertThat(FindingConsolidator.consolidate(findings)).singleElement()
			.satisfies((vuln) -> assertThat(vuln.description()).contains("2 endpoints"));
	}

	@Test
	void aHostWideFindingSeenOnASingleEndpointIsLeftUntouched() {
		Vulnerability only = finding("security-headers", "Missing Security Header: CSP", RiskLevel.LOW, "GET",
				HOST + "/pet");

		assertThat(FindingConsolidator.consolidate(List.of(only))).containsExactly(only);
	}

	@Test
	void aFindingWithoutDescriptionConsolidatesWithoutALiteralNull() {
		List<Vulnerability> findings = List.of(
				finding("security-headers", "Missing Security Header: HSTS", RiskLevel.LOW, "GET", HOST + "/a", null),
				finding("security-headers", "Missing Security Header: HSTS", RiskLevel.LOW, "GET", HOST + "/b", null));

		List<Vulnerability> consolidated = FindingConsolidator.consolidate(findings);

		assertThat(consolidated).singleElement()
			.extracting(Vulnerability::description)
			.asString()
			.doesNotContain("null")
			.startsWith("Observed on 2 endpoints");
	}

	private static Vulnerability finding(String scannerId, String name, RiskLevel risk, String method, String url) {
		return finding(scannerId, name, risk, method, url, "Description of " + name);
	}

	private static Vulnerability finding(String scannerId, String name, RiskLevel risk, String method, String url,
			String description) {
		return new Vulnerability("id-" + name.hashCode() + url.hashCode(), name, description, risk,
				Vulnerability.Confidence.HIGH, scannerId, url, method, null, List.of(), List.of(), null, "evidence",
				"fix", "req", "resp", "vector", "impact");
	}

}

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

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import ch.nexsol.orthrus.protocol.node.Vulnerability;

/**
 * Collapses findings that describe the whole host rather than one endpoint (a missing
 * security header, the server banner, the CORS policy) into a single finding per host,
 * kept at the highest severity seen and listing every endpoint it was observed on.
 * Endpoint-specific findings (injections, authorization flaws...) are never merged.
 */
public final class FindingConsolidator {

	/**
	 * Deterministic scanners whose findings are properties of the host; their findings
	 * merge when the title is identical.
	 */
	private static final Set<String> HOST_WIDE_SCANNERS = Set.of("security-headers", "ssl-tls",
			"cleartext-transmission", "cors");

	private static final String AI_SCANNER_PREFIX = "ai-";

	/**
	 * AI agents word the same host-wide issue differently on every endpoint, so their
	 * findings merge by topic, recognised from keywords in the title. The order is the
	 * priority when a title mentions several topics, so grouping is deterministic.
	 */
	private static final List<Map.Entry<String, List<String>>> AI_HOST_WIDE_TOPICS = List.of(
			Map.entry("cors", List.of("cors")),
			Map.entry("server-banner",
					List.of("server header", "version disclosure", "technology disclosure", "framework version")),
			Map.entry("security-headers", List.of("missing security header", "security headers")));

	private FindingConsolidator() {
	}

	/**
	 * Merges host-wide findings, keeping the order of first appearance.
	 * @param findings the findings of a scan
	 * @return the findings with each host-wide issue reported once per host
	 */
	public static List<Vulnerability> consolidate(List<Vulnerability> findings) {
		if (findings == null || findings.isEmpty()) {
			return (findings != null) ? findings : List.of();
		}
		Map<String, List<Vulnerability>> groups = new LinkedHashMap<>();
		int standalone = 0;
		for (Vulnerability finding : findings) {
			String key = hostWideKey(finding);
			// Endpoint-specific findings get a unique key so they are never merged.
			groups.computeIfAbsent((key != null) ? key : "#" + standalone++, (k) -> new ArrayList<>()).add(finding);
		}
		List<Vulnerability> consolidated = new ArrayList<>(groups.size());
		for (List<Vulnerability> group : groups.values()) {
			consolidated.add((group.size() == 1) ? group.get(0) : merge(group));
		}
		return consolidated;
	}

	private static String hostWideKey(Vulnerability finding) {
		String host = hostOf(finding.operationUrl());
		String scannerId = finding.scannerId();
		if (host == null || scannerId == null) {
			return null;
		}
		if (HOST_WIDE_SCANNERS.contains(scannerId)) {
			return host + "|" + scannerId + "|" + finding.name();
		}
		if (scannerId.startsWith(AI_SCANNER_PREFIX) && finding.name() != null) {
			String title = finding.name().toLowerCase(Locale.ROOT);
			for (Map.Entry<String, List<String>> topic : AI_HOST_WIDE_TOPICS) {
				if (topic.getValue().stream().anyMatch(title::contains)) {
					return host + "|ai|" + topic.getKey();
				}
			}
		}
		return null;
	}

	private static Vulnerability merge(List<Vulnerability> group) {
		Vulnerability worst = group.stream().max(Comparator.comparing(Vulnerability::riskLevel)).orElseThrow();
		List<String> endpoints = group.stream()
			.map((finding) -> finding.operationMethod() + " " + finding.operationUrl())
			.distinct()
			.toList();
		String description = ((worst.description() != null) ? worst.description() + "\n\n" : "") + "Observed on "
				+ endpoints.size() + " endpoints: " + String.join(", ", endpoints) + ".";
		return new Vulnerability(worst.id(), worst.name(), description, worst.riskLevel(), worst.confidence(),
				worst.scannerId(), worst.operationUrl(), worst.operationMethod(), worst.cwe(), worst.cves(),
				worst.capecs(), worst.cvssScore(), worst.evidence(), worst.remediation(), worst.requestDetails(),
				worst.responseDetails(), worst.attackVector(), worst.technicalImpact());
	}

	private static String hostOf(String url) {
		if (url == null || url.isBlank()) {
			return null;
		}
		try {
			UriComponents uri = UriComponentsBuilder.fromUriString(url).build();
			return (uri.getHost() != null) ? uri.getScheme() + "://" + uri.getHost() + ":" + uri.getPort() : null;
		}
		catch (IllegalArgumentException ex) {
			return null;
		}
	}

}

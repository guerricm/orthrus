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

import java.net.URI;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

import ch.nexsol.orthrusdast.model.GatewayExclusions;

/**
 * Small helpers shared by the UI controllers.
 */
final class WebFormUtils {

	private WebFormUtils() {
	}

	static int parseIntOrDefault(String value, int defaultValue) {
		if (value == null || value.isBlank()) {
			return defaultValue;
		}
		try {
			return Integer.parseInt(value.trim());
		}
		catch (NumberFormatException ex) {
			return defaultValue;
		}
	}

	/**
	 * Splits a free-text list (one entry per line, or comma-separated) into its trimmed,
	 * non-blank entries.
	 * @param value the text typed in the form, possibly null
	 * @return the entries, empty when there are none
	 */
	static List<String> parseList(String value) {
		if (value == null || value.isBlank()) {
			return List.of();
		}
		return Arrays.stream(value.split("[,\\r\\n]+")).map(String::trim).filter((entry) -> !entry.isEmpty()).toList();
	}

	/**
	 * The gateway exclusions entered in the plan form.
	 * @param routeIds the excluded route ids, as typed
	 * @param paths the excluded path patterns, as typed
	 * @return the exclusions, or null when both fields are empty
	 */
	static GatewayExclusions gatewayExclusions(String routeIds, String paths) {
		GatewayExclusions exclusions = new GatewayExclusions(parseList(routeIds), parseList(paths));
		return exclusions.isEmpty() ? null : exclusions;
	}

	/**
	 * Timestamp segment of a generated file name: sortable and safe on every file system.
	 */
	private static final DateTimeFormatter FILE_TIMESTAMP = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss")
		.withZone(ZoneOffset.UTC);

	/**
	 * Turns a free-text name into a lowercase, hyphenated token safe for a file name.
	 * @param name the name, may be null or blank
	 * @param fallback the token to use when nothing usable remains
	 * @return the slug
	 */
	static String slugify(String name, String fallback) {
		if (name == null || name.isBlank()) {
			return fallback;
		}
		String slug = name.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]+", "-").replaceAll("(^-|-$)", "");
		return slug.isBlank() ? fallback : slug;
	}

	/**
	 * The file name of a downloaded report:
	 * {@code orthrus-report-<plan>-<scan time>.<ext>}. The plan name identifies the scan;
	 * without one (an ad-hoc scan) the target host does. The scan time is the UTC start
	 * of the scan, left out when unknown.
	 * @param planName the name of the plan the scan ran, may be null or blank
	 * @param target the scan target, used when there is no plan
	 * @param scanStart when the scan started, may be null
	 * @param extension the file extension without the dot
	 * @return the file name
	 */
	static String reportFilename(String planName, String target, Instant scanStart, String extension) {
		String subject = (planName != null && !planName.isBlank()) ? slugify(planName, "scan")
				: slugify(hostOf(target), "scan");
		String timestamp = (scanStart != null) ? "-" + FILE_TIMESTAMP.format(scanStart) : "";
		return "orthrus-report-" + subject + timestamp + "." + extension;
	}

	private static String hostOf(String target) {
		if (target == null) {
			return null;
		}
		try {
			return URI.create(target.trim()).getHost();
		}
		catch (IllegalArgumentException ex) {
			return null;
		}
	}

}

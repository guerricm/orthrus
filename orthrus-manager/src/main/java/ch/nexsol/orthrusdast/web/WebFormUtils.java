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

import java.util.Arrays;
import java.util.List;

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

}

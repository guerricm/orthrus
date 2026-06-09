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

package ch.nexsol.orthrusdast.model;

import java.util.List;

/**
 * Configuration for a scan session.
 */
public record ScanConfiguration(List<String> includeScanners, List<String> excludeScanners, int concurrency,
		int httpConnectTimeoutMs, int httpReadTimeoutMs, boolean ignoreSslErrors, String reportFormat,
		SecurityScheme authScheme, SecurityScheme secondaryAuthScheme, String language, boolean includePassed,
		GatewayType gatewayType, String appUrl, String k8sToken, OAuth2Config oauth2Config,
		String openapiOverrideHost) {

	public static ScanConfiguration defaults() {
		return new ScanConfiguration(List.of(), List.of(), 10, 5000, 10000, false, "json", null, null, "en", false,
				GatewayType.AUTO, null, null, null, null);
	}

	/**
	 * Check if a scanner ID should be executed given include/exclude rules.
	 */
	public boolean shouldRunScanner(String scannerId) {
		if (excludeScanners.contains(scannerId)) {
			return false;
		}
		if (!includeScanners.isEmpty()) {
			return includeScanners.contains(scannerId);
		}
		return true;
	}
}

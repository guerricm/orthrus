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

import java.util.List;

import reactor.core.publisher.Flux;

import ch.nexsol.orthrusdast.http.ScanHttpResponse;
import ch.nexsol.orthrusdast.model.CWEReference;
import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.RiskLevel;
import ch.nexsol.orthrusdast.model.Vulnerability;

/**
 * Interface for all security scanners.
 */
public interface SecurityScanner {

	/**
	 * @return the unique identifier of the scanner
	 */
	String getId();

	/**
	 * @return the human-readable name of the scanner
	 */
	String getName();

	/**
	 * Executes the scan on the given operation with context configuration.
	 * @param operation the operation to scan
	 * @param config the scan configuration
	 * @return a Flux of found vulnerabilities
	 */
	default Flux<Vulnerability> scan(Operation operation, ch.nexsol.orthrusdast.model.ScanConfiguration config) {
		return scan(operation);
	}

	/**
	 * Executes the scan on the given operation.
	 * @param operation the operation to scan
	 * @param confidence the confidence
	 * @param originalOp the originalOp
	 * @param cwe the cwe
	 * @param capecs the capecs
	 * @param name the name
	 * @param description the description
	 * @param riskLevel the riskLevel
	 * @return a Flux of found vulnerabilities
	 * @return the result
	 */
	Flux<Vulnerability> scan(Operation operation);

	/**
	 * Helper to create a Vulnerability with formatted HTTP traces.
	 * @param attackVector the attackVector
	 * @param technicalImpact the technicalImpact
	 * @param cvssScore the cvssScore
	 * @param evidence the evidence
	 * @param remediation the remediation
	 * @param testOp the testOp
	 * @param response the response
	 */
	default Vulnerability createVulnerabilityWithTrace(String name, String description, RiskLevel riskLevel,
			Vulnerability.Confidence confidence, Operation originalOp, CWEReference cwe, List<String> capecs,
			Double cvssScore, String evidence, String remediation, Operation testOp, ScanHttpResponse response,
			String attackVector, String technicalImpact) {
		String reqDetails = formatRequest(testOp);
		String resDetails = response != null ? formatResponse(response) : "No Response";

		return Vulnerability.createWithDetails(name, description, riskLevel, confidence, getId(), originalOp, cwe,
				capecs, cvssScore, evidence, remediation, reqDetails, resDetails, attackVector, technicalImpact);
	}

	private String formatRequest(Operation op) {
		StringBuilder sb = new StringBuilder();
		String url = op.url();
		if (url != null && url.length() > 200) {
			url = url.substring(0, 200) + "...[TRUNCATED]";
		}

		// Reconstruct URL with query params
		StringBuilder fullUrl = new StringBuilder(url != null ? url : "");
		if (op.queryParams() != null && !op.queryParams().isEmpty() && op.url() != null && !op.url().contains("?")) {
			fullUrl.append("?");
			op.queryParams().forEach((k, v) -> {
				String val = v;
				if (val != null && val.length() > 100)
					val = val.substring(0, 100) + "...[TRUNCATED]";
				fullUrl.append(k).append("=").append(val).append("&");
			});
			fullUrl.setLength(fullUrl.length() - 1); // remove last &
		}

		sb.append(op.method().name()).append(" ").append(fullUrl).append(" HTTP/1.1\n");

		try {
			if (url != null) {
				java.net.URI uri = java.net.URI.create(url);
				if (uri.getHost() != null) {
					sb.append("Host: ").append(uri.getHost()).append("\n");
				}
			}
		}
		catch (Exception ex) {
			// Ignore URI parsing errors
		}

		sb.append("User-Agent: Orthrus-DAST/1.0\n");
		sb.append("Accept: */*\n");

		if (op.authScheme() != null
				&& op.authScheme().paramLocation() == ch.nexsol.orthrusdast.model.SecurityScheme.ParamLocation.HEADER) {
			String headerName = op.authScheme().headerName() != null ? op.authScheme().headerName() : "Authorization";
			sb.append(headerName).append(": ").append(op.authScheme().toAuthorizationHeaderValue()).append("\n");
		}

		boolean hasContentType = false;
		if (op.headers() != null) {
			for (java.util.Map.Entry<String, String> entry : op.headers().entrySet()) {
				if ("Content-Type".equalsIgnoreCase(entry.getKey())) {
					hasContentType = true;
				}
				sb.append(entry.getKey()).append(": ").append(entry.getValue()).append("\n");
			}
		}

		if (op.body() != null && !op.body().isEmpty() && !hasContentType) {
			sb.append("Content-Type: application/json\n");
		}

		sb.append("\n");
		if (op.body() != null && !op.body().isEmpty()) {
			sb.append((op.body().length() > 1000) ? op.body().substring(0, 1000) + "... [TRUNCATED]" : op.body());
		}
		return sb.toString();
	}

	private String formatResponse(ScanHttpResponse res) {
		StringBuilder sb = new StringBuilder();
		sb.append("Status: ").append(res.statusCode()).append("\n");
		if (res.headers() != null) {
			res.headers().forEach((k, values) -> {
				values.forEach((v) -> sb.append(k).append(": ").append(v).append("\n"));
			});
		}
		sb.append("\n");
		if (res.body() != null) {
			sb.append((res.body().length() > 1000) ? res.body().substring(0, 1000) + "... [TRUNCATED]" : res.body());
		}
		return sb.toString();
	}

}

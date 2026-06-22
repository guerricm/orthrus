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

/**
 * Shared detection heuristics used by injection scanners (SQLi, OS command injection,
 * etc.). Centralizing these rules keeps time-based and content-based detection consistent
 * and avoids the copy-paste drift that previously existed between scanners.
 */
public final class DetectionUtils {

	/**
	 * Minimum absolute delay (ms) before a time-based payload is considered successful.
	 */
	public static final long TIME_BASED_THRESHOLD_MS = 4000;

	/**
	 * Extra margin (ms) above the measured baseline response time, so naturally slow
	 * endpoints are not flagged as time-based injections.
	 */
	public static final long TIME_BASED_MARGIN_MS = 3000;

	private DetectionUtils() {
	}

	/**
	 * @param status the HTTP status code
	 * @return true if the status is a 4xx client error
	 */
	public static boolean isClientError(int status) {
		return status >= 400 && status < 500;
	}

	/**
	 * Decides whether a delayed response is a credible time-based injection hit. The
	 * required delay is the larger of the absolute threshold and the measured baseline
	 * plus a margin, which suppresses false positives on slow endpoints. Gateway timeouts
	 * (503/504) and client errors are never counted as hits.
	 * @param responseTimeMs the observed response time
	 * @param baselineMs the baseline response time measured for a benign request
	 * @param status the HTTP status code of the response
	 * @return true if the delay is attributable to an injected time-based payload
	 */
	public static boolean isTimeBasedHit(long responseTimeMs, long baselineMs, int status) {
		if (status == 503 || status == 504 || isClientError(status)) {
			return false;
		}
		long required = Math.max(TIME_BASED_THRESHOLD_MS, baselineMs + TIME_BASED_MARGIN_MS);
		return responseTimeMs > required;
	}

	/**
	 * Case-insensitive containment check against a list of signatures.
	 * @param body the response body (may be null)
	 * @param lowerCaseSignatures signatures to look for, expected to be lower-case
	 * @return true if the body contains any of the signatures
	 */
	public static boolean containsAny(String body, List<String> lowerCaseSignatures) {
		if (body == null || body.isEmpty()) {
			return false;
		}
		String lower = body.toLowerCase();
		for (String signature : lowerCaseSignatures) {
			if (!signature.isEmpty() && lower.contains(signature)) {
				return true;
			}
		}
		return false;
	}

}

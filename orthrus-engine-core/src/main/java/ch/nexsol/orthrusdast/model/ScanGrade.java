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

import java.util.Map;

/**
 * Turns a risk breakdown into the single A–F letter shown on scan results.
 */
public final class ScanGrade {

	private ScanGrade() {
	}

	/**
	 * Grades a scan on its worst finding: critical scores F, high D, medium C, low B, and
	 * a clean scan A. Informational findings do not affect the grade.
	 * @param riskSummary the number of findings per risk level
	 * @return the grade letter
	 */
	public static String of(Map<RiskLevel, Long> riskSummary) {
		if (riskSummary == null) {
			return "A";
		}
		if (riskSummary.getOrDefault(RiskLevel.CRITICAL, 0L) > 0) {
			return "F";
		}
		if (riskSummary.getOrDefault(RiskLevel.HIGH, 0L) > 0) {
			return "D";
		}
		if (riskSummary.getOrDefault(RiskLevel.MEDIUM, 0L) > 0) {
			return "C";
		}
		if (riskSummary.getOrDefault(RiskLevel.LOW, 0L) > 0) {
			return "B";
		}
		return "A";
	}

}

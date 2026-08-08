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

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ScanGradeTest {

	@Test
	void aScanWithNoFindingsScoresA() {
		assertThat(ScanGrade.of(Map.of())).isEqualTo("A");
	}

	@Test
	void aNullSummaryIsTreatedAsClean() {
		assertThat(ScanGrade.of(null)).isEqualTo("A");
	}

	@Test
	void informationalFindingsAloneDoNotLowerTheGrade() {
		assertThat(ScanGrade.of(Map.of(RiskLevel.INFO, 12L))).isEqualTo("A");
	}

	@Test
	void eachSeverityMapsToItsOwnLetter() {
		assertThat(ScanGrade.of(Map.of(RiskLevel.LOW, 1L))).isEqualTo("B");
		assertThat(ScanGrade.of(Map.of(RiskLevel.MEDIUM, 1L))).isEqualTo("C");
		assertThat(ScanGrade.of(Map.of(RiskLevel.HIGH, 1L))).isEqualTo("D");
		assertThat(ScanGrade.of(Map.of(RiskLevel.CRITICAL, 1L))).isEqualTo("F");
	}

	@Test
	void theWorstFindingDecidesTheGrade() {
		Map<RiskLevel, Long> mixed = Map.of(RiskLevel.INFO, 40L, RiskLevel.LOW, 9L, RiskLevel.MEDIUM, 4L,
				RiskLevel.HIGH, 2L, RiskLevel.CRITICAL, 1L);
		assertThat(ScanGrade.of(mixed)).isEqualTo("F");

		Map<RiskLevel, Long> withoutCritical = Map.of(RiskLevel.INFO, 40L, RiskLevel.LOW, 9L, RiskLevel.MEDIUM, 4L,
				RiskLevel.HIGH, 2L);
		assertThat(ScanGrade.of(withoutCritical)).isEqualTo("D");
	}

	@Test
	void aSeverityPresentWithAZeroCountDoesNotCount() {
		assertThat(ScanGrade.of(Map.of(RiskLevel.CRITICAL, 0L, RiskLevel.LOW, 3L))).isEqualTo("B");
	}

}

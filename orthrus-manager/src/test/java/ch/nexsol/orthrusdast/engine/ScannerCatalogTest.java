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

package ch.nexsol.orthrusdast.engine;

import java.util.List;

import org.junit.jupiter.api.Test;

import ch.nexsol.orthrusdast.scanner.ScannerFamily;
import ch.nexsol.orthrusdast.scanner.SecurityScanner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The catalog exposes each scanner's family, maps families to scanner ids, and derives
 * the families covered by a scanner selection (used to restrict which family tasks a job
 * creates).
 */
class ScannerCatalogTest {

	private SecurityScanner scanner(String id, ScannerFamily family) {
		SecurityScanner s = mock(SecurityScanner.class);
		when(s.getId()).thenReturn(id);
		when(s.getName()).thenReturn(id + " scanner");
		when(s.getFamily()).thenReturn(family);
		return s;
	}

	private ScannerCatalog catalog() {
		return new ScannerCatalog(
				List.of(scanner("sqli", ScannerFamily.INJECTION), scanner("nosqli", ScannerFamily.INJECTION),
						scanner("xss", ScannerFamily.XSS), scanner("cors", ScannerFamily.CONFIGURATION)));
	}

	@Test
	void mapsFamiliesToScannerIds() {
		assertThat(catalog().scannerIdsForFamilies(List.of("INJECTION"))).containsExactlyInAnyOrder("sqli", "nosqli");
		assertThat(catalog().scannerIdsForFamilies(List.of("injection", "xss"))).containsExactlyInAnyOrder("sqli",
				"nosqli", "xss");
		assertThat(catalog().scannerIdsForFamilies(List.of())).isEmpty();
	}

	@Test
	void derivesFamiliesFromScannerSelection() {
		assertThat(catalog().familyNamesForScanners(List.of("sqli", "xss"))).containsExactlyInAnyOrder("INJECTION",
				"XSS");
		assertThat(catalog().familyNamesForScanners(List.of("cors"))).containsExactly("CONFIGURATION");
		assertThat(catalog().familyNamesForScanners(List.of())).isEmpty();
	}

	@Test
	void exposesScannersSortedWithFamily() {
		assertThat(catalog().scanners()).extracting(ScannerCatalog.ScannerInfo::id)
			.containsExactly("cors", "nosqli", "sqli", "xss");
		assertThat(catalog().scanners().get(0).family()).isEqualTo("CONFIGURATION");
	}

}

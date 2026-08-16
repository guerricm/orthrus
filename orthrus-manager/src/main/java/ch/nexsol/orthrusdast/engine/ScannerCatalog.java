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

import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.stereotype.Component;

import ch.nexsol.orthrusdast.scanner.ScannerFamily;
import ch.nexsol.orthrusdast.scanner.SecurityScanner;

/**
 * In-process catalog of the deterministic scanners, built from the
 * {@link SecurityScanner} beans the manager already holds on its classpath. Unlike the
 * worker's {@code /capabilities} response (id + name only, and only when a worker is
 * live), this exposes the scanner family too and needs no running worker — so the Test
 * Plan form works, AI-planned families map to scanner ids, and the dispatcher can derive
 * which families a selection of scanners covers.
 */
@Component
public class ScannerCatalog {

	private final List<ScannerInfo> scanners;

	private final Map<String, ScannerFamily> familyById;

	public ScannerCatalog(List<SecurityScanner> securityScanners) {
		this.scanners = securityScanners.stream()
			.map((s) -> new ScannerInfo(s.getId(), s.getName(), s.getFamily().name()))
			.sorted(Comparator.comparing(ScannerInfo::id))
			.toList();
		this.familyById = securityScanners.stream()
			.collect(Collectors.toMap(SecurityScanner::getId, SecurityScanner::getFamily, (a, b) -> a));
	}

	/**
	 * All scanners, sorted by id, each carrying its family.
	 * @return the scanner descriptors
	 */
	public List<ScannerInfo> scanners() {
		return this.scanners;
	}

	/**
	 * The scanner ids belonging to any of the given families.
	 * @param families family names (case-insensitive), e.g. from an AI plan
	 * @return the matching scanner ids
	 */
	public Set<String> scannerIdsForFamilies(Collection<String> families) {
		if (families == null || families.isEmpty()) {
			return Set.of();
		}
		Set<String> wanted = families.stream()
			.filter((f) -> f != null)
			.map((f) -> f.trim().toUpperCase(Locale.ROOT))
			.collect(Collectors.toSet());
		return this.familyById.entrySet()
			.stream()
			.filter((e) -> wanted.contains(e.getValue().name()))
			.map(Map.Entry::getKey)
			.collect(Collectors.toCollection(LinkedHashSet::new));
	}

	/**
	 * The distinct family names covered by the given scanner ids.
	 * @param scannerIds selected scanner ids
	 * @return the family names with at least one selected scanner
	 */
	public Set<String> familyNamesForScanners(Collection<String> scannerIds) {
		if (scannerIds == null || scannerIds.isEmpty()) {
			return Set.of();
		}
		return scannerIds.stream()
			.map(this.familyById::get)
			.filter((f) -> f != null)
			.map(ScannerFamily::name)
			.collect(Collectors.toSet());
	}

	/**
	 * A scanner descriptor for the UI. Exposes {@code getX} accessors alongside the
	 * record ones so Thymeleaf templates can read it either way.
	 *
	 * @param id the scanner id (checkbox value)
	 * @param name the human-readable name
	 * @param family the scanner family name
	 */
	public record ScannerInfo(String id, String name, String family) {

		public String getId() {
			return this.id;
		}

		public String getName() {
			return this.name;
		}

		public String getFamily() {
			return this.family;
		}

	}

}

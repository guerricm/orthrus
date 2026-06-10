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
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import reactor.core.publisher.Flux;

import ch.nexsol.orthrusdast.ingestion.EndpointDiscoverer;
import ch.nexsol.orthrusdast.model.ScanAttempt;
import ch.nexsol.orthrusdast.model.ScanConfiguration;

import ch.nexsol.orthrusdast.scanner.SecurityScanner;
import java.util.Comparator;

/**
 * High-level orchestration service. Finds the right discoverer and triggers the
 * ScanEngine.
 */
@Service
public class ScanService {

	private static final Logger log = LoggerFactory.getLogger(ScanService.class);

	private final ScanEngine scanEngine;

	private final Map<String, EndpointDiscoverer> discoverers;

	public ScanService(ScanEngine scanEngine, List<EndpointDiscoverer> discovererList) {
		this.scanEngine = scanEngine;
		this.discoverers = discovererList.stream()
			.collect(Collectors.toMap(EndpointDiscoverer::getId, Function.identity()));
	}

	/**
	 * Execute a scan based on a target and a specific discoverer ID.
	 * @param discovererId the discovererId
	 * @param target the target
	 * @param config the config
	 * @return the result
	 */
	public Flux<ScanAttempt> executeScan(String discovererId, String target, ScanConfiguration config) {
		EndpointDiscoverer discoverer = discoverers.get(discovererId);
		if (discoverer == null) {
			return Flux.error(new IllegalArgumentException("Unknown discoverer ID: " + discovererId));
		}

		log.info("Executing scan with discoverer '{}' on target '{}'", discovererId, target);

		return scanEngine.runScan(discoverer, target, config);
	}

	/**
	 * Get a list of available discoverers.
	 * @return the result
	 */
	public List<String> getAvailableDiscoverers() {
		return discoverers.keySet().stream().sorted().toList();
	}

	/**
	 * Get a list of available scanner IDs.
	 * @return the result
	 */
	public List<String> getAvailableScanners() {
		return scanEngine.getAllScanners().stream().map(SecurityScanner::getId).sorted().toList();
	}

	/**
	 * Get a list of available scanner objects (useful for UI display with
	 * names/descriptions).
	 * @return the result
	 */
	public List<SecurityScanner> getAvailableScannerObjects() {
		return scanEngine.getAllScanners().stream().sorted(Comparator.comparing(SecurityScanner::getId)).toList();
	}

}

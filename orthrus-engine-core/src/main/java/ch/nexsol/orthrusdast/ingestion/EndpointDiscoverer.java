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

package ch.nexsol.orthrusdast.ingestion;

import java.util.List;

import reactor.core.publisher.Mono;

import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.ScanConfiguration;

/**
 * Interface for API discovery mechanisms.
 */
public interface EndpointDiscoverer {

	/**
	 * @return the unique identifier of the discoverer
	 */
	String getId();

	/**
	 * Executes the discovery process.
	 * @param target the target to discover (URL, OpenAPI spec, etc.)
	 * @param overrideHost optional host to override
	 * @param config the scan configuration
	 * @return a Mono emitting a List of discovered operations
	 */
	Mono<List<Operation>> discover(String target, ScanConfiguration config);

}

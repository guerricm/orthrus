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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import reactor.core.publisher.Mono;

import ch.nexsol.orthrusdast.model.Operation;

import ch.nexsol.orthrusdast.model.ScanConfiguration;
import ch.nexsol.orthrusdast.model.SecurityScheme;
import org.springframework.http.HttpMethod;

/**
 * "Discoverer" that just takes a single URL (like a curl command) and treats it as the
 * only operation.
 */
@Component
public class CurlDiscoverer implements EndpointDiscoverer {

	private static final Logger log = LoggerFactory.getLogger(CurlDiscoverer.class);

	@Override
	public String getId() {
		return "curl";
	}

	@Override
	public Mono<List<Operation>> discover(String target, ScanConfiguration config) {
		SecurityScheme authScheme = config != null ? config.authScheme() : null;
		log.info("Registering single target for curl-like scan: {}", target);

		// Assume GET if not otherwise specified. Advanced curl-like usage (setting
		// method/headers)
		// would require parsing target string if it contained CLI-like flags,
		// but for now we just take the URL as target.

		Operation op = Operation.simple(target, HttpMethod.GET).withAuth(authScheme);
		return Mono.just(List.of(op));
	}

}

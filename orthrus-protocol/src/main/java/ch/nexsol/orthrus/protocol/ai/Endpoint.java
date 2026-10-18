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

package ch.nexsol.orthrus.protocol.ai;

import java.util.List;

/**
 * One endpoint a recon found on the target, ready to hand to a scanner agent. Beyond the
 * method and URL, it carries the operation's shape read from the API spec, the parameters
 * and a compact request-body schema, so the agent forges realistic requests instead of
 * guessing the structure.
 *
 * @param method the HTTP method to exercise it with
 * @param url the absolute URL
 * @param parameters the declared parameters, never null
 * @param requestBodySchema a compact rendering of the request body schema, or null when
 * the operation takes no body or none was found
 */
public record Endpoint(String method, String url, List<Parameter> parameters, String requestBodySchema) {

	public Endpoint {
		parameters = (parameters != null) ? List.copyOf(parameters) : List.of();
	}

	/**
	 * An endpoint with no known shape, for recon that could not read a spec.
	 * @param method the HTTP method
	 * @param url the absolute URL
	 */
	public Endpoint(String method, String url) {
		this(method, url, List.of(), null);
	}

	/**
	 * One declared parameter of an operation.
	 *
	 * @param name the parameter name
	 * @param in where it goes: query, path, header or cookie
	 * @param type the declared type, e.g. string or integer
	 * @param required whether the spec marks it required
	 */
	public record Parameter(String name, String in, String type, boolean required) {
	}
}

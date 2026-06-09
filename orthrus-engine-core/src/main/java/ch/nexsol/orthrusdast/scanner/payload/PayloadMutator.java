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

package ch.nexsol.orthrusdast.scanner.payload;

import org.springframework.stereotype.Service;

@Service
public class PayloadMutator {

	public enum Context {

		URL_PARAM, HEADER, JSON_BODY, XML_BODY

	}

	/**
	 * Mutates a raw payload based on where it's going to be injected.
	 * @param rawPayload the rawPayload
	 * @param context the context
	 * @return the result
	 */
	public String mutate(String rawPayload, Context context) {
		if (rawPayload == null || rawPayload.isEmpty()) {
			return rawPayload;
		}

		return switch (context) {
			case JSON_BODY -> escapeForJson(rawPayload);
			case XML_BODY -> escapeForXml(rawPayload);
			case URL_PARAM, HEADER -> rawPayload; // Usually left raw as Spring's
													// WebClient encodes URL params
													// automatically, and headers need raw
													// values
		};
	}

	private String escapeForJson(String rawPayload) {
		// If the payload itself contains double quotes, we might want to break out of the
		// JSON string.
		// E.g., rawPayload: " OR 1=1 --
		// If it's going into {"field": "PAYLOAD"}, we want it to be {"field": "" OR 1=1
		// --"}
		// But since Jackson will serialize our injected string safely, if we WANT to
		// break out,
		// we actually shouldn't just let Jackson escape it.
		// Wait, the scanner injects the payload into an ObjectNode. Jackson will safely
		// escape it:
		// jsonBody.put("field", payload) -> {"field": "\" OR 1=1"} (safe)
		// To do an actual JSON injection, the payload must break the JSON structure,
		// meaning it needs to be
		// passed raw into the JSON string, not via Jackson's put().
		// For now, since the scanners use Jackson to build the body, we will just return
		// the payload.
		// A true JSON mutator would modify the raw JSON string directly, bypassing
		// Jackson.
		return rawPayload;
	}

	private String escapeForXml(String rawPayload) {
		return rawPayload;
	}

}

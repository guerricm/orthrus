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

	/**
	 * Escapes a payload so it can be embedded as a JSON string value when the body is
	 * built by raw string templating (i.e. not through Jackson, which already escapes).
	 * This keeps the resulting document well-formed so the payload reaches the backend as
	 * a value rather than corrupting the surrounding structure. Backslashes and double
	 * quotes are escaped and control characters are stripped.
	 * @param rawPayload the raw payload
	 * @return the JSON-string-safe payload
	 */
	private String escapeForJson(String rawPayload) {
		StringBuilder sb = new StringBuilder(rawPayload.length() + 16);
		for (int i = 0; i < rawPayload.length(); i++) {
			char c = rawPayload.charAt(i);
			switch (c) {
				case '"' -> sb.append("\\\"");
				case '\\' -> sb.append("\\\\");
				case '\n' -> sb.append("\\n");
				case '\r' -> sb.append("\\r");
				case '\t' -> sb.append("\\t");
				default -> {
					if (c < 0x20) {
						sb.append(String.format("\\u%04x", (int) c));
					}
					else {
						sb.append(c);
					}
				}
			}
		}
		return sb.toString();
	}

	/**
	 * Escapes a payload so it can be embedded safely as XML character data or an
	 * attribute value. This is used when fuzzing XML request bodies so the surrounding
	 * markup stays well-formed and the payload is delivered as data.
	 * @param rawPayload the raw payload
	 * @return the XML-safe payload
	 */
	private String escapeForXml(String rawPayload) {
		StringBuilder sb = new StringBuilder(rawPayload.length() + 16);
		for (int i = 0; i < rawPayload.length(); i++) {
			char c = rawPayload.charAt(i);
			switch (c) {
				case '&' -> sb.append("&amp;");
				case '<' -> sb.append("&lt;");
				case '>' -> sb.append("&gt;");
				case '"' -> sb.append("&quot;");
				case '\'' -> sb.append("&apos;");
				default -> sb.append(c);
			}
		}
		return sb.toString();
	}

}

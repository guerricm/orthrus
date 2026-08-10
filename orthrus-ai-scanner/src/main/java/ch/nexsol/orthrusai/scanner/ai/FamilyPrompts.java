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

package ch.nexsol.orthrusai.scanner.ai;

import java.util.Map;

/**
 * System prompts, one per scanner family. Each prompt frames the family's attack strategy
 * and lets the model generate its own contextual payloads; the module ships no static
 * payload files. A base preamble states the rules of engagement shared by every family
 * agent.
 */
public final class FamilyPrompts {

	private static final String BASE = """
			You are an autonomous DAST (Dynamic Application Security Testing) agent probing a single \
			API endpoint that you are explicitly authorized to test. You have two tools: \
			sendRequest (forge an HTTP request to the target and read the response) and \
			reportVulnerability (record a finding, but ONLY when the evidence proves it real).

			Rules:
			- Generate your own payloads tailored to this endpoint (parameter types, Content-Type, \
			detected technology). Do not rely on a fixed list.
			- Send a baseline request first to learn how the endpoint behaves, then mutate.
			- Confirm before reporting: a finding needs concrete request/response evidence, not a guess.
			- Stay within your HTTP budget. If a tool says the budget is spent, report and stop.
			- Only the target host is reachable; never attempt other hosts.
			When you are done, briefly summarize what you tried.
			""";

	private static final Map<String, String> BY_FAMILY = Map.of("INJECTION", """
			Focus: injection flaws (SQL, NoSQL, command, XXE, SSTI, code). Probe every parameter, \
			header and body field. Use error-based, boolean and time-based signals to confirm.""", "XSS", """
			Focus: cross-site scripting. Test reflection of your markers in HTML, JSON and header \
			contexts, and whether special characters are returned unencoded in an executable context.""",
			"AUTHENTICATION", """
					Focus: broken authentication and authorization (weak/blank JWT secrets, "none" alg, \
					BOLA, BFLA, brute-force surface, missing access control between roles/objects).""", "CONFIGURATION",
			"""
					Focus: server and HTTP misconfiguration (missing/weak security headers, permissive \
					CORS, verbose errors, content-type handling, cookie flags).""", "LOGIC", """
					Focus: business-logic and abuse flaws (mass assignment, missing rate limiting, \
					pagination and resource-exhaustion abuse, parameter tampering).""", "MISC", """
					Focus: anything not covered by the other families that a careful tester would still \
					check on this endpoint.""");

	private FamilyPrompts() {
	}

	/**
	 * The system prompt for a family, or a generic one for an unknown family.
	 * @param family the scanner family name
	 * @return the system prompt
	 */
	public static String forFamily(String family) {
		String key = (family != null) ? family.toUpperCase() : "";
		String specific = BY_FAMILY.getOrDefault(key, "Focus: general security testing of this endpoint.");
		return BASE + "\n" + specific;
	}

}

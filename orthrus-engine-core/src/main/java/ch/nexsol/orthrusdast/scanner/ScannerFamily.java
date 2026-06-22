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

package ch.nexsol.orthrusdast.scanner;

/**
 * Defines the family or category of a security scanner. This allows the orchestrator to
 * distribute and schedule specific types of tests to specific worker nodes.
 */
public enum ScannerFamily {

	/**
	 * Scanners that discover endpoints, perform crawling, or parsing (e.g., OpenAPI).
	 */
	DISCOVERY,

	/**
	 * Scanners that attempt injection attacks (SQLi, NoSQLi, Command Injection, etc.).
	 */
	INJECTION,

	/**
	 * Scanners that check for Cross-Site Scripting vulnerabilities.
	 */
	XSS,

	/**
	 * Scanners focusing on authentication and authorization (BruteForce, BOLA, JWT).
	 */
	AUTHENTICATION,

	/**
	 * Scanners validating server and HTTP configuration (Headers, CORS, SSL, etc.).
	 */
	CONFIGURATION,

	/**
	 * Scanners checking for business logic flaws (Mass Assignment, Rate Limiting).
	 */
	LOGIC,

	/**
	 * Scanners that do not fit into other specific categories.
	 */
	MISC

}

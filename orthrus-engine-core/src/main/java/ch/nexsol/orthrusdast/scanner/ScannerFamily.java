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

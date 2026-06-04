# Orthrus DAST

<p align="center">
  <img src="orthrus-master/src/main/resources/static/images/logo.png" alt="Orthrus DAST Logo" width="300"/>
</p>

Orthrus DAST is a modern, reactive Dynamic Application Security Testing (DAST) tool designed for APIs. Built with Spring Boot 4 and WebFlux, it scans your API endpoints for common vulnerabilities like SQL Injection, Broken Authentication, BOLA, XSS, SSRF, CORS misconfigurations, and more.

## Features

- **Reactive Engine**: Highly concurrent scanning engine built on Spring WebFlux.
- **36 Specialized Scanners**:

| Scanner ID | Description | Associated CWE |
| --- | --- | --- |
| `auth-bruteforce` | Brute force / weak password detection on authentication endpoints (uses SecLists top-100) | CWE-307 (Improper Restriction of Excessive Authentication Attempts) |
| `bfla` | Broken Function Level Authorization via HTTP method replacement | CWE-285 (Improper Authorization) |
| `bola` | Broken Object Level Authorization (IDOR) via ID manipulation | CWE-639 (Authorization Bypass Through User-Controlled Key) |
| `broken-auth` | Missing Authentication for Critical Functions | CWE-306 (Missing Authentication for Critical Function) |
| `cleartext-transmission` | Detects unencrypted HTTP APIs | CWE-319 (Cleartext Transmission of Sensitive Information) |
| `cmd-injection` | OS Command Injection | CWE-78 (Improper Neutralization of Special Elements used in an OS Command) |
| `code-injection` | Injects eval/code payloads (PHP, Python, Node.js) to detect arbitrary code execution | CWE-94 (Improper Control of Generation of Code ('Code Injection')) |
| `content-type-spoofing` | XXE and parser errors via Content-Type manipulation | CWE-436 (Interpretation Conflict) / CWE-611 |
| `cookie-security` | Missing Secure, HttpOnly, and SameSite attributes in cookies | CWE-614 (Sensitive Cookie in HTTPS Session Without 'Secure' Attribute) |
| `cors` | Overly permissive CORS origins | CWE-942 (Permissive Cross-domain Policy with Untrusted Domains) |
| `cross-user-bola` | Advanced BOLA testing using a secondary user's token | CWE-639 (Authorization Bypass Through User-Controlled Key) |
| `csrf-protection` | Checks state-changing endpoints for missing Anti-CSRF tokens | CWE-352 (Cross-Site Request Forgery (CSRF)) |
| `file-upload` | Attempts to bypass validation by uploading EICAR signatures and malicious extensions | CWE-434 (Unrestricted Upload of File with Dangerous Type) |
| `graphql-dos` | Tests GraphQL endpoints for deeply nested queries triggering Resource Consumption DoS | CWE-770 (Allocation of Resources Without Limits or Throttling) |
| `graphql-injection` | Injects SQLi, XSS, and CmdInj payloads dynamically into GraphQL JSON variables | CWE-74 (Improper Neutralization of Special Elements in Output Used by a Downstream Component) |
| `graphql-introspection` | Detects if GraphQL introspection is enabled in production | CWE-200 (Exposure of Sensitive Information to an Unauthorized Actor) |
| `insecure-deserialization` | Sends magic byte payloads for Java, Python, and JSON gadgets | CWE-502 (Deserialization of Untrusted Data) |
| `jwt-blank-secret` | JWT blank secret bypass | CWE-310 (Cryptographic Issues) |
| `jwt-none-alg` | JWT 'none' algorithm bypass | CWE-347 (Improper Verification of Cryptographic Signature) |
| `mass-assignment` | Broken Object Property Level Auth (Mass Assignment) via JSON payloads | CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes) |
| `method-tampering` | Exposure of unsafe HTTP methods like TRACE | CWE-650 (Trusting HTTP Permission Methods on the Server Side) |
| `nosql-injection` | MongoDB operator injection | CWE-943 (Improper Neutralization of Special Elements in Data Query Logic) |
| `open-redirect` | Unvalidated redirects | CWE-601 (URL Redirection to Untrusted Site ('Open Redirect')) |
| `path-traversal` | Directory Traversal for arbitrary file reads | CWE-22 (Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')) |
| `rate-limiting` | Lack of rate limiting on sensitive endpoints | CWE-770 (Allocation of Resources Without Limits or Throttling) |
| `request-smuggling` | Detects HTTP Request Smuggling vulnerabilities using malformed Transfer-Encoding headers | CWE-444 (Inconsistent Interpretation of HTTP Requests) |
| `schema-validation` | Enforces OpenAPI schema constraints (maxLength, required properties, data types) | CWE-20 (Improper Input Validation) |
| `security-headers` | Missing critical security headers (HSTS, CSP, etc.) | CWE-693 (Protection Mechanism Failure) |
| `sensitive-query-params` | Detects sensitive information (passwords, tokens) exposed in URL query strings | CWE-598 (Use of GET Request Method With Sensitive Query Strings) |
| `sqli` | SQL Injection in query parameters | CWE-89 (Improper Neutralization of Special Elements used in an SQL Command) |
| `ssl-tls` | Scans SSL/TLS certificates for expiration, weak protocols, self-signed issues, and weak signature algorithms | CWE-295 (Improper Certificate Validation) |
| `ssrf` | Server-Side Request Forgery via AWS metadata endpoints | CWE-918 (Server-Side Request Forgery (SSRF)) |
| `ssti` | Server-Side Template Injection via mathematical payloads | CWE-1336 (Improper Neutralization of Special Elements Used in a Template Engine) |
| `verbose-error` | Leaks of stack traces or sensitive errors | CWE-209 (Generation of Error Message Containing Sensitive Information) |
| `xss` | Reflected Cross-Site Scripting via query params, JSON bodies, and headers | CWE-79 (Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')) |
| `xxe-injection` | Injects malicious DTDs referencing external files like /etc/passwd | CWE-611 (Improper Restriction of XML External Entity Reference) |
- **5 Discovery Modes**:
  - `openapi`: Parses OpenAPI v3 specifications (JSON/YAML)
  - `graphql`: Utilizes the GraphQL introspection query to dump the schema, dynamically building valid queries and mutations for testing.
  - `blackbox`: Crawls and fuzzes a target URL to discover endpoints dynamically
  - `gateway`: Connects to API Gateways (Traefik, Kong, Spring Cloud, HAProxy, K8s) to extract routing rules dynamically
  - `curl`: Reads cURL commands from a file
  - `well-known`: Scans for standard sensitive files (e.g. `/.env`, `/.git/config`)

### Gateway Mode Details
The `gateway` mode is an incredibly powerful feature for DevSecOps. It probes the Gateway's Admin API to read its actual routing tables (e.g. `PathPrefix('/api')`), and automatically fuzzes the underlying routes.

**Supported Gateways:**
- Traefik (`/api/http/routers`)
- Spring Cloud Gateway (`/actuator/gateway/routes`)
- Kong API Gateway (`/routes`)
- HAProxy (`/v2/services/haproxy/configuration/acls`)
- Kubernetes Ingress (`/apis/networking.k8s.io/v1/ingresses`)

**Gateway Flags:**
- `--gateway-type`: `auto` (default), `traefik`, `spring-cloud-gateway`, `kong`, `haproxy`, `k8s`.
- `--app-url`: If the Admin API (e.g., port 8080) is on a different port than the public app (e.g., port 80), specify the public URL to attack with `--app-url=http://myapp.com`.
- `--k8s-token`: Provide your Kubernetes ServiceAccount token for K8s discovery (or use the `K8S_TOKEN` environment variable). Note: K8s is not auto-detected for security reasons, it must be explicitly specified with `--gateway-type=k8s`.

### Authentication
- **Reporting**: JSON, SARIF (for GitHub Advanced Security), HTML, PDF, and Console formats.
- **API & CLI**: Run as a command-line tool or as a long-running REST API service.

## Architecture (Orthrus V2)

Orthrus V2 introduces a highly scalable **Master-Slave** architecture:
- **Master (`orthrus-master`)**: Coordinates the scan jobs, exposes a Web UI on port 8080, and maintains a database (H2 by default) of registered Slaves and Scan Jobs.
- **Slave (`orthrus-slave`)**: Connects to the Master to retrieve jobs, executes the actual high-concurrency scans, and reports results back.
- **CLI (`orthrus-cli`)**: A lightweight wrapper for the Engine providing a CLI interface for local execution or CI/CD integration without a Master.
- **Engine Core (`orthrus-engine-core`)**: Shared execution engine containing the models, discoverers, scanners, and report generators used by all components.

## Prerequisites

- Java 25 or higher
- Maven 3.8+
- Docker (optional, for containerized deployments)

## Building

Compile and package the entire multi-module application:
```bash
./mvnw clean package -DskipTests
```
This generates three executable JARs:
- `orthrus-master/target/orthrus-master-0.0.1-SNAPSHOT.jar`
- `orthrus-slave/target/orthrus-slave-0.0.1-SNAPSHOT.jar`
- `orthrus-cli/target/orthrus-cli-0.0.1-SNAPSHOT.jar`

You can also build Docker images locally:
```bash
mvn spring-boot:build-image -pl orthrus-master
mvn spring-boot:build-image -pl orthrus-slave
mvn spring-boot:build-image -pl orthrus-cli
```

## Usage (Distributed Mode)

### 1. Start the Master
The Master node orchestrates everything and exposes the Web UI on `http://localhost:8080`.
```bash
java -jar orthrus-master/target/orthrus-master-0.0.1-SNAPSHOT.jar
```

### 2. Start one or more Slaves
Slaves will automatically connect to the Master on port 8080. You can run multiple slaves on different machines or ports.
```bash
java -jar orthrus-slave/target/orthrus-slave-0.0.1-SNAPSHOT.jar --server.port=8081
```

Once running, navigate to `http://localhost:8080` to launch scans via the interface. You can view connected slaves and active jobs in the **System / Slaves** tab.

## Usage (Standalone CLI Mode)

If you just want to run a scan from your terminal without spinning up the Master/UI infrastructure, you can use the CLI JAR autonomously.

```bash
java -jar orthrus-cli/target/orthrus-cli-0.0.1-SNAPSHOT.jar -d <DISCOVERER> -t <TARGET_URL> [OPTIONS]
```

### CLI Examples

**Generate a professional PDF report in French:**
```bash
java -jar orthrus-cli/target/orthrus-cli-0.0.1-SNAPSHOT.jar -d openapi -t https://api.example.com/v3/api-docs -f pdf --lang fr -o rapport_securite.pdf
```

**Automated OAuth2 Token Fetching for Cross-User BOLA (IDOR):**
Automatically fetch tokens for two users to test for BOLA across boundaries:
```bash
java -jar orthrus-cli/target/orthrus-cli-0.0.1-SNAPSHOT.jar -d openapi -t https://api.example.com/v3/api-docs \
  --oauth2-url "https://keycloak.example.com/realms/master/protocol/openid-connect/token" \
  --oauth2-grant "password" \
  --oauth2-client-id "orthrus-client" \
  --oauth2-creds "alice:pwd123,bob:pwd456"
```

**Crawl a website (Blackbox):**
```bash
java -jar orthrus-cli/target/orthrus-cli-0.0.1-SNAPSHOT.jar -d blackbox -t https://example.com --out report.json -f json
```

### CLI Options
- `-d, --discoverer`: Discoverer to use (`openapi`, `blackbox`, `curl`, `well-known`, `gateway`).
- `-t, --target`: Target URL or Spec path.
- `-c, --concurrency`: Number of concurrent threads to use during the scan (default: 10). Increase for massive APIs to speed up execution.
- `--host`: Override the host URL for the target endpoints.
- `-f, --format`: Report format (`json`, `sarif`, `html`, `pdf`, `console`). Default is `console`.
- `--lang`: Report language when using PDF or HTML format (`en`, `fr`). Default is `en`.
- `-o, --out`: Output file path. If not provided, prints to standard output.
- `--auth-bearer`: Provide a Bearer token to inject into all requests (Primary User).
- `--auth-bearer-secondary`: Provide a secondary Bearer token for Cross-User BOLA testing (Secondary User).
- `--oauth2-url`: OAuth2 token endpoint URL.
- `--oauth2-client-id`: OAuth2 Client ID.
- `--oauth2-client-secret`: OAuth2 Client Secret.
- `--oauth2-grant`: OAuth2 Grant Type (`password` or `client_credentials`).
- `--oauth2-creds`: Comma-separated list of `username:password` credentials (for `password` grant).
- `--include`: Comma-separated list of scanner IDs to run exclusively.
- `--exclude`: Comma-separated list of scanner IDs to skip.
- `--include-passed`: Include all executed tests (passed and failed) in the report. Adds an "Execution Details" section to HTML, PDF, JSON, and SARIF reports.
- `--gateway-type`: Gateway type: `auto`, `traefik`, `kong`, `spring-cloud-gateway`, `haproxy`, `k8s` (default: `auto`).
- `--app-url`: Public Application URL for Gateway Discovery (e.g. http://myapp.com) if different from the admin interface.
- `--k8s-token`: Kubernetes ServiceAccount Token (or set K8S_TOKEN env var).

The Web UI provides a user-friendly, responsive experience with the following features:
- **Interactive Dashboard**: View statistics and a history of all executed scans.
- **Easy Configuration**: A "New Scan" form that lets you easily select discovery modules, target URLs, and authentication methods.
- **Advanced Options**: Fully integrates the advanced CLI flags through an intuitive UI:
  - Configure **OAuth2** (URL, Client ID, Secret, Grant Type) for dynamic token fetching.
  - Provide a **Secondary Bearer Token** for automated Cross-User BOLA testing.
  - Checkboxes to easily select or deselect which specific scanners to run.
- **Live Execution & Reporting**: See scan progress in real-time, view detailed findings with their respective risk grades (A to F), and export results directly as a **PDF**.
- **Integrated User Manual**: A detailed, built-in guide accessible directly from the interface (`/manual`) explaining discovery modes and security grading.

## Usage (REST API Mode)

If you run the application without CLI arguments, it starts a Spring WebFlux server exposing a REST API.

```bash
java -jar target/orthrus-dast-0.0.1-SNAPSHOT.jar
```

**Trigger a basic scan:**
```bash
curl -X POST http://localhost:8080/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{
    "discovererId": "well-known",
    "target": "https://example.com",
    "format": "json"
  }'
```

**Generate a PDF report in French with a Bearer token:**
```bash
curl -X POST http://localhost:8080/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{
    "discovererId": "openapi",
    "target": "https://api.example.com/v3/api-docs",
    "format": "pdf",
    "language": "fr",
    "authScheme": {
      "type": "BEARER",
      "value": "TOKEN_USER_A",
      "headerName": "Authorization",
      "paramLocation": "HEADER"
    }
  }' --output report.pdf
```

**Test for Cross-User BOLA (IDOR) with two distinct users via API:**
```bash
curl -X POST http://localhost:8080/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{
    "discovererId": "openapi",
    "target": "https://api.example.com/v3/api-docs",
    "format": "json",
    "authScheme": {
      "type": "BEARER",
      "value": "TOKEN_USER_A",
      "headerName": "Authorization",
      "paramLocation": "HEADER"
    },
    "secondaryAuthScheme": {
      "type": "BEARER",
      "value": "TOKEN_USER_B",
      "headerName": "Authorization",
      "paramLocation": "HEADER"
    }
  }'
```

**Automated OAuth2 Token Fetching via API:**
```bash
curl -X POST http://localhost:8080/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{
    "discovererId": "openapi",
    "target": "https://api.example.com/v3/api-docs",
    "format": "json",
    "oauth2": {
      "tokenUrl": "https://keycloak.example.com/realms/master/protocol/openid-connect/token",
      "clientId": "orthrus-client",
      "grantType": "password",
      "credentials": ["alice:pwd123", "bob:pwd456"]
    }
  }'
```

**Generate a report with full execution details:**
```bash
curl -X POST http://localhost:8080/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{
    "discovererId": "openapi",
    "target": "https://api.example.com/v3/api-docs",
    "format": "json",
    "includePassed": true
  }'
```

**List available discoverers:**
```bash
curl http://localhost:8080/api/v1/scans/discoverers
```

## Adding Custom Scanners

Orthrus is designed to be highly extensible. To add a new scanner, implement the `SecurityScanner` interface and annotate the class with `@Component`. The engine will automatically pick it up and include it in scans.

```java
import ch.nexsol.vulnapi.scanner.SecurityScanner;
import org.springframework.stereotype.Component;

@Component
public class MyCustomScanner implements SecurityScanner {
    @Override
    public String getId() { return "my-custom-scanner"; }
    // Implement scan logic...
}
```

## Disclaimer

> [!WARNING]
> **Legal and Liability Disclaimer**
> 
> This tool (Orthrus) is designed exclusively for educational purposes and authorized security testing. Do **NOT** use it against systems, networks, or applications that you do not own or do not have explicit, documented permission to test.
>
> - **Theoretical Scoring**: The CVSS (Common Vulnerability Scoring System) Base Scores provided in the generated reports are purely theoretical and generalized for the type of vulnerability identified. They do not account for your specific environmental metrics, infrastructure mitigations, or temporal factors.
> - **No Warranty**: The tool relies on automated Dynamic Application Security Testing (DAST) techniques which are not infallible. It may produce false positives or, more importantly, **false negatives** (missing critical vulnerabilities).
> - **Limitation of Liability**: The authors, contributors, and the tool itself cannot be held liable for any undetected vulnerabilities, subsequent system compromises, data breaches, or any direct/indirect damages arising from the use of this software. 
> 
> **By using this tool, you accept full responsibility for your actions and any consequences that may result.**

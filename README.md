# Orthrus DAST

Orthrus DAST is a modern, reactive Dynamic Application Security Testing (DAST) tool designed for APIs. Built with Spring Boot 4 and WebFlux, it scans your API endpoints for common vulnerabilities like SQL Injection, Broken Authentication, BOLA, XSS, SSRF, CORS misconfigurations, and more.

## Features

- **Reactive Engine**: Highly concurrent scanning engine built on Spring WebFlux.
- **25 Specialized Scanners**:
  - `broken-auth`: Missing Authentication for Critical Functions
  - `sqli`: SQL Injection in query parameters
  - `jwt-none-alg`: JWT 'none' algorithm bypass
  - `jwt-blank-secret`: JWT blank secret bypass
  - `cors`: Overly permissive CORS origins
  - `security-headers`: Missing critical security headers (HSTS, CSP, etc.)
  - `rate-limiting`: Lack of rate limiting on sensitive endpoints
  - `ssrf`: Server-Side Request Forgery via AWS metadata endpoints
  - `xss`: Reflected Cross-Site Scripting via query params, JSON bodies, and headers
  - `bola`: Broken Object Level Authorization (IDOR) via ID manipulation
  - `cross-user-bola`: Advanced BOLA testing using a secondary user's token
  - `method-tampering`: Exposure of unsafe HTTP methods like TRACE
  - `path-traversal`: Directory Traversal for arbitrary file reads
  - `cmd-injection`: OS Command Injection
  - `open-redirect`: Unvalidated redirects
  - `mass-assignment`: Broken Object Property Level Auth (Mass Assignment) via JSON payloads
  - `nosql-injection`: MongoDB operator injection
  - `verbose-error`: Leaks of stack traces or sensitive errors
  - `bfla`: Broken Function Level Authorization via HTTP method replacement
  - `content-type-spoofing`: XXE and parser errors via Content-Type manipulation
  - `ssti`: Server-Side Template Injection via mathematical payloads
  - `cleartext-transmission`: Detects unencrypted HTTP APIs
  - `auth-bruteforce`: Brute force / weak password detection on authentication endpoints (uses SecLists top-100 dictionary)
  - `graphql-introspection`: Detects if GraphQL introspection is enabled in production
  - `graphql-injection`: Injects SQLi, XSS, and CmdInj payloads dynamically into GraphQL JSON variables
  - `ssl-tls`: Scans SSL/TLS certificates for expiration, weak protocols, self-signed issues, and weak signature algorithms
- **5 Discovery Modes**:
  - `openapi`: Automatically extracts routes and generates mock payloads from an OpenAPI v3 specification.
  - `graphql`: Utilizes the GraphQL introspection query to dump the schema, dynamically building valid queries and mutations for testing.
  - `blackbox`: Crawls HTML pages and forms up to a configurable depth.
  - `well-known`: Probes common unprotected paths (`/actuator`, `/.env`, etc.).
  - `curl`: Directly scans a single specified URL.
- **Reporting**: JSON, SARIF (for GitHub Advanced Security), HTML, PDF, and Console formats.
- **API & CLI**: Run as a command-line tool or as a long-running REST API service.

## Prerequisites

- Java 25 or higher
- Maven 3.8+

## Building

Compile and package the application:
```bash
./mvnw clean package -DskipTests
```
This generates the executable JAR in the `target/` directory.

## Usage (CLI Mode)

To run a scan from the command line, pass arguments to the JAR. The command requires a discoverer (`-d`) and a target (`-t`).

```bash
java -jar target/orthrus-dast-0.0.1-SNAPSHOT.jar -d <DISCOVERER> -t <TARGET_URL> [OPTIONS]
```

### Examples

**Generate a professional PDF report in French:**
```bash
java -jar target/orthrus-dast-0.0.1-SNAPSHOT.jar -d openapi -t https://api.example.com/v3/api-docs -f pdf --lang fr -o rapport_securite.pdf
```

**Scan an OpenAPI specification:**
```bash
java -jar target/orthrus-dast-0.0.1-SNAPSHOT.jar -d openapi -t https://api.example.com/v3/api-docs -f console
```

**Crawl a website (Blackbox):**
```bash
java -jar target/orthrus-dast-0.0.1-SNAPSHOT.jar -d blackbox -t https://example.com --out report.json -f json
```

**Scan a single endpoint with a Bearer Token:**
```bash
java -jar target/orthrus-dast-0.0.1-SNAPSHOT.jar -d curl -t "https://api.example.com/v1/users/123" --auth-bearer "eyJhb..."
```

**Generate a SARIF report for CI/CD:**
```bash
java -jar target/orthrus-dast-0.0.1-SNAPSHOT.jar -d well-known -t https://example.com -f sarif --out vulnapi-results.sarif
```

**Test for Cross-User BOLA (IDOR) with two distinct users:**
```bash
java -jar target/orthrus-dast-0.0.1-SNAPSHOT.jar -d openapi -t https://api.example.com/v3/api-docs --auth-bearer "TOKEN_USER_A" --auth-bearer-secondary "TOKEN_USER_B"
```

**Automated OAuth2 Token Fetching (e.g. Keycloak):**
Automatically fetch tokens for one or multiple users before scanning (supports `password` or `client_credentials`):
```bash
java -jar target/orthrus-dast-0.0.1-SNAPSHOT.jar -d openapi -t https://api.example.com/v3/api-docs \
  --oauth2-url "https://keycloak.example.com/realms/master/protocol/openid-connect/token" \
  --oauth2-grant "password" \
  --oauth2-client-id "orthrus-client" \
  --oauth2-creds "alice:pwd123,bob:pwd456"
```
*(If exactly 2 sets of credentials are provided, they are mapped to the primary and secondary auth schemes for automated Cross-User BOLA testing).*

**Generate a detailed report with all executed tests (passed & failed):**
```bash
java -jar target/orthrus-dast-0.0.1-SNAPSHOT.jar -d openapi -t https://api.example.com/v3/api-docs -f html -o report.html --include-passed
```

**Optimize performance by increasing concurrency (e.g. 100 threads for massive APIs):**
```bash
java -jar target/orthrus-dast-0.0.1-SNAPSHOT.jar -d openapi -t https://api.example.com/v3/api-docs -c 100
```
*This adds an "Execution Details" section at the end of the report, listing every scanner test against every endpoint, sorted by endpoint → method → scanner → status (failed first).*

### CLI Options
- `-d, --discoverer`: Discoverer to use (`openapi`, `blackbox`, `curl`, `well-known`).
- `-t, --target`: Target URL or Spec path.
- `-c, --concurrency`: Number of concurrent threads to use during the scan (default: 10). Increase for massive APIs to speed up execution.
- `--host`: Override the host URL for the target endpoints.
- `-f, --format`: Report format (`json`, `sarif`, `html`, `pdf`, `console`). Default is `console`.
- `--lang`: Report language when using PDF or HTML format (`en`, `fr`). Default is `en`.
- `-o, --out`: Output file path. If not provided, prints to standard output.
- `--auth-bearer`: Provide a Bearer token to inject into all requests (Primary User).
- `--auth-bearer-secondary`: Provide a secondary Bearer token for Cross-User BOLA testing (Secondary User).
- `--oauth2-url`: OAuth2 token endpoint URL (e.g., Keycloak token endpoint).
- `--oauth2-client-id`: OAuth2 Client ID.
- `--oauth2-client-secret`: OAuth2 Client Secret.
- `--oauth2-grant`: OAuth2 Grant Type (`password` or `client_credentials`).
- `--oauth2-creds`: Comma-separated list of `username:password` credentials (for `password` grant).
- `--include`: Comma-separated list of scanner IDs to run exclusively.
- `--exclude`: Comma-separated list of scanner IDs to skip.
- `--include-passed`: Include all executed tests (passed and failed) in the report. Adds an "Execution Details" section to HTML, PDF, JSON, and SARIF reports.

## Usage (Web UI Mode)

If you run the application without CLI arguments, it starts a Spring WebFlux server exposing a rich Web User Interface on **http://localhost:8080**.

```bash
java -jar target/orthrus-dast-0.0.1-SNAPSHOT.jar
```

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
import ch.hug.vulnapi.scanner.SecurityScanner;
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

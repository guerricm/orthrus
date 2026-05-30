# Orthrus VulnAPI

Orthrus VulnAPI is a modern, reactive Dynamic Application Security Testing (DAST) tool designed for APIs. Built with Spring Boot 4 and WebFlux, it scans your API endpoints for common vulnerabilities like SQL Injection, Broken Authentication, BOLA, XSS, SSRF, CORS misconfigurations, and more.

## Features

- **Reactive Engine**: Highly concurrent scanning engine built on Spring WebFlux.
- **21 Specialized Scanners**:
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
- **4 Discovery Modes**:
  - `openapi`: Automatically extracts routes and generates mock payloads from an OpenAPI v3 specification.
  - `blackbox`: Crawls HTML pages and forms up to a configurable depth.
  - `well-known`: Probes common unprotected paths (`/actuator`, `/.env`, etc.).
  - `curl`: Directly scans a single specified URL.
- **Reporting**: JSON, SARIF (for GitHub Advanced Security), HTML, and Console formats.
- **API & CLI**: Run as a command-line tool or as a long-running REST API service.

## Prerequisites

- Java 17 or higher
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
java -jar target/orthrus-0.0.1-SNAPSHOT.jar -d <DISCOVERER> -t <TARGET_URL> [OPTIONS]
```

### Examples

**Generate a professional PDF report in French:**
```bash
java -jar target/orthrus-0.0.1-SNAPSHOT.jar -d openapi -t https://api.example.com/v3/api-docs -f pdf --lang fr -o rapport_securite.pdf
```

**Scan an OpenAPI specification:**
```bash
java -jar target/orthrus-0.0.1-SNAPSHOT.jar -d openapi -t https://api.example.com/v3/api-docs -f console
```

**Crawl a website (Blackbox):**
```bash
java -jar target/orthrus-0.0.1-SNAPSHOT.jar -d blackbox -t https://example.com --out report.json -f json
```

**Scan a single endpoint with a Bearer Token:**
```bash
java -jar target/orthrus-0.0.1-SNAPSHOT.jar -d curl -t "https://api.example.com/v1/users/123" --auth-bearer "eyJhb..."
```

**Generate a SARIF report for CI/CD:**
```bash
java -jar target/orthrus-0.0.1-SNAPSHOT.jar -d well-known -t https://example.com -f sarif --out vulnapi-results.sarif
```

### CLI Options
- `-d, --discoverer`: Discoverer to use (`openapi`, `blackbox`, `curl`, `well-known`).
- `-t, --target`: Target URL or Spec path.
- `--host`: Override the host URL for the target endpoints.
- `-f, --format`: Report format (`json`, `sarif`, `html`, `pdf`, `console`). Default is `console`.
- `--lang`: Report language when using PDF or HTML format (`en`, `fr`). Default is `en`.
- `-o, --out`: Output file path. If not provided, prints to standard output.
- `--auth-bearer`: Provide a Bearer token to inject into all requests.
- `--include`: Comma-separated list of scanner IDs to run exclusively.
- `--exclude`: Comma-separated list of scanner IDs to skip.

## Usage (REST API Mode)

If you run the application without CLI arguments, it starts a Spring WebFlux server exposing a REST API.

```bash
java -jar target/orthrus-0.0.1-SNAPSHOT.jar
```

**Trigger a scan:**
```bash
curl -X POST http://localhost:8080/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{
    "discovererId": "well-known",
    "target": "https://example.com",
    "concurrency": 5,
    "authScheme": {
      "type": "BEARER",
      "value": "your-token",
      "paramLocation": "HEADER"
    }
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

This tool is designed for educational purposes and authorized security testing only. Do not use it against targets you do not have permission to test.

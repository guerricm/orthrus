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

import java.util.List;

import org.springframework.stereotype.Component;

import reactor.core.publisher.Flux;

import ch.nexsol.orthrusdast.http.ScanHttpClient;
import ch.nexsol.orthrusdast.model.CWEReference;
import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.RiskLevel;
import ch.nexsol.orthrusdast.model.Vulnerability;

import java.util.HashMap;
import java.util.Map;

/**
 * Scans for Unrestricted File Upload vulnerabilities (CWE-434).
 */
@Component
public class FileUploadScanner implements SecurityScanner {

	private final ScanHttpClient httpClient;

	// Minimal malicious file payload (EICAR standard antivirus test string)
	private static final String EICAR_PAYLOAD = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

	// SVG XSS Payload
	private static final String SVG_XSS_PAYLOAD = "<?xml version=\"1.0\" standalone=\"no\"?>\n"
			+ "<!DOCTYPE svg PUBLIC \"-//W3C//DTD SVG 1.1//EN\" \"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd\">\n"
			+ "<svg version=\"1.1\" baseProfile=\"full\" xmlns=\"http://www.w3.org/2000/svg\">\n"
			+ "   <script type=\"text/javascript\">\n" + "      alert(\"XSS\");\n" + "   </script>\n" + "</svg>";

	// PHP Web Shell Payload
	private static final String PHP_SHELL_PAYLOAD = "<?php system($_GET['cmd']); ?>";

	public FileUploadScanner(ScanHttpClient httpClient) {
		this.httpClient = httpClient;
	}

	@Override
	public String getId() {
		return "file-upload";
	}

	@Override
	public String getName() {
		return "Unrestricted File Upload Scanner";
	}

	@Override
	public Flux<Vulnerability> scan(Operation operation) {
		return Flux.defer(() -> {
			// Only target endpoints that likely accept multipart/form-data
			if (!List.of("POST", "PUT").contains(operation.method().name())) {
				return Flux.empty();
			}

			// We could also check operation.expectedContentTypes() for
			// multipart/form-data
			// but it's safe to test all POSTs if they accept arbitrary data.

			return Flux.concat(
					testUpload(operation, "eicar.com", "application/x-msdownload", EICAR_PAYLOAD,
							"EICAR Antivirus Test File",
							"upload of an executable or potentially dangerous file (EICAR test string)"),
					testUpload(operation, "xss.svg", "image/svg+xml", SVG_XSS_PAYLOAD, "SVG XSS Upload",
							"upload of an SVG image containing embedded JavaScript (Stored XSS)"),
					testUpload(operation, "shell.php", "application/x-httpd-php", PHP_SHELL_PAYLOAD,
							"PHP Web Shell Upload", "upload of a PHP Web Shell"),
					testUpload(operation, "shell.php.jpg", "image/jpeg", PHP_SHELL_PAYLOAD,
							"PHP Web Shell Upload (Double Extension)",
							"upload of a PHP Web Shell bypassing extension checks using a double extension (.php.jpg)"));
		});
	}

	private Flux<Vulnerability> testUpload(Operation operation, String filename, String contentType, String payload,
			String title, String context) {
		String boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW";
		String multipartBody = "--" + boundary + "\r\n" + "Content-Disposition: form-data; name=\"file\"; filename=\""
				+ filename + "\"\r\n" + "Content-Type: " + contentType + "\r\n\r\n" + payload + "\r\n" + "--" + boundary
				+ "--\r\n";

		Map<String, String> newHeaders = new HashMap<>(operation.headers());
		newHeaders.put("Content-Type", "multipart/form-data; boundary=" + boundary);

		Operation testOp = new Operation(operation.url(), operation.method(), newHeaders, operation.queryParams(),
				multipartBody, operation.securityRequirements(), operation.expectedContentTypes(),
				operation.authScheme());

		return httpClient.send(testOp).flatMapMany((response) -> {
			if (response.isSuccessful()) {
				Vulnerability vuln = createVulnerabilityWithTrace("Unrestricted File Upload - " + title,
						"The endpoint allowed the " + context + " without blocking it.", RiskLevel.HIGH,
						Vulnerability.Confidence.MEDIUM, operation, CWEReference.CWE_434, List.of("CAPEC-17"), 8.8,
						"Server responded with " + response.statusCode() + " OK after uploading " + filename + ".",
						"Implement strict file type validation (using magic bytes, not just extensions). Use an antivirus scanner on all uploaded files. Store files outside the web root and serve them with strict Content-Disposition headers.",
						testOp, response, "API Endpoint (Network)", "Unauthorized Access / Data Exposure");
				return Flux.just(vuln);
			}
			return Flux.empty();
		});
	}

}

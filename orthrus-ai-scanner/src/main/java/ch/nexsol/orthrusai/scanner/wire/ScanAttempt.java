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

package ch.nexsol.orthrusai.scanner.wire;

import java.util.List;

/**
 * One scanner run against one operation. Serialized to the exact JSON the manager
 * records.
 *
 * @param scannerId id of the scanner
 * @param scannerName human-readable scanner name
 * @param operationMethod the HTTP method tested
 * @param operationUrl the URL tested
 * @param status one of PASSED, FAILED, AUTH_ERROR, ERROR
 * @param vulnerabilities findings produced by this run (empty when none)
 */
public record ScanAttempt(String scannerId, String scannerName, String operationMethod, String operationUrl,
		String status, List<Vulnerability> vulnerabilities) {
}

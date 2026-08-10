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

import ch.nexsol.orthrusdast.http.ScanHttpResponse;

/**
 * Per-operation context handed to a scanner by the engine.
 *
 * <p>
 * The engine already issues one baseline request per operation (to detect auth walls
 * before running scanners). Sharing that response here lets scanners that only need the
 * unmodified response — cookie flags, security headers, verbose bodies, timing baselines
 * — avoid re-issuing an identical request.
 *
 * @param baselineResponse the response to the unmodified operation, or null when the
 * engine could not obtain one
 */
public record ScanContext(ScanHttpResponse baselineResponse) {

	public boolean hasBaseline() {
		return baselineResponse != null;
	}

}

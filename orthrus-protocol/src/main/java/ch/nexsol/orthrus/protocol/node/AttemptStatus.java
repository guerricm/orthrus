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

package ch.nexsol.orthrus.protocol.node;

/**
 * Outcome of one scanner on one endpoint.
 */
public enum AttemptStatus {

	/** The test ran and found nothing. */
	PASSED,

	/** The test ran and found a vulnerability. */
	FAILED,

	/** The test did not run: the target rejected the credentials (401). */
	AUTH_ERROR,

	/** The test did not run: the credentials were accepted but lack permission (403). */
	FORBIDDEN,

	/** The test failed to run. */
	ERROR,

	/** The test was not run: the task spent its budget before reaching it. */
	NOT_RUN

}

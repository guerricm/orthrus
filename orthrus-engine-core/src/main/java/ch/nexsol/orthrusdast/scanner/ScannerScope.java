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
 * Granularity at which a scanner needs to run.
 */
public enum ScannerScope {

	/**
	 * The scanner tests something specific to each operation (endpoint + method) and must
	 * run once per operation. This is the default.
	 */
	OPERATION,

	/**
	 * The scanner tests a property shared by every operation on the same host:port (TLS
	 * certificate, scheme enforcement, ...). Running it once per host instead of once per
	 * operation avoids sending the same probes dozens of times against a single target.
	 */
	HOST

}

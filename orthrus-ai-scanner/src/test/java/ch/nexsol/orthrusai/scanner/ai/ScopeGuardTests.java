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

package ch.nexsol.orthrusai.scanner.ai;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Guards the scope check: only the target host:port is reachable, on any path.
 */
class ScopeGuardTests {

	private final ScopeGuard guard = new ScopeGuard();

	@Test
	void samehostDifferentPathIsInScope() {
		assertThat(this.guard.inScope("http://app.test/api/users/1", "http://app.test/api")).isTrue();
	}

	@Test
	void defaultPortsAreEquivalent() {
		assertThat(this.guard.inScope("http://app.test:80/x", "http://app.test/y")).isTrue();
		assertThat(this.guard.inScope("https://app.test:443/x", "https://app.test/y")).isTrue();
	}

	@Test
	void otherHostIsOutOfScope() {
		assertThat(this.guard.inScope("http://evil.test/steal", "http://app.test/api")).isFalse();
	}

	@Test
	void otherPortIsOutOfScope() {
		assertThat(this.guard.inScope("http://app.test:8080/x", "http://app.test/y")).isFalse();
	}

	@Test
	void malformedCandidateIsOutOfScope() {
		assertThat(this.guard.inScope("not a url", "http://app.test/api")).isFalse();
	}

}

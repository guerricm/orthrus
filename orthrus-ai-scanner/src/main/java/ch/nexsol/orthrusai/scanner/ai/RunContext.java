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

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import ch.nexsol.orthrusai.scanner.wire.Vulnerability;

/**
 * Per-endpoint state shared with the tools an agent calls during one scan. It carries the
 * scope, the HTTP-call budget, and the findings the agent reports, so tool instances stay
 * stateless beyond this context and one agent run cannot spill into another.
 */
public class RunContext {

	private final String targetUrl;

	private final String scannerId;

	private final int maxHttpCalls;

	private final AtomicInteger httpCalls = new AtomicInteger();

	private final List<Vulnerability> findings = new CopyOnWriteArrayList<>();

	public RunContext(String targetUrl, String scannerId, int maxHttpCalls) {
		this.targetUrl = targetUrl;
		this.scannerId = scannerId;
		this.maxHttpCalls = maxHttpCalls;
	}

	public String targetUrl() {
		return this.targetUrl;
	}

	public String scannerId() {
		return this.scannerId;
	}

	/**
	 * Reserves one HTTP call against the budget.
	 * @return true when a call is allowed, false when the budget is exhausted
	 */
	public boolean tryConsumeHttpCall() {
		return this.httpCalls.incrementAndGet() <= this.maxHttpCalls;
	}

	public int httpCallsUsed() {
		return this.httpCalls.get();
	}

	public void addFinding(Vulnerability finding) {
		this.findings.add(finding);
	}

	public List<Vulnerability> findings() {
		return List.copyOf(this.findings);
	}

}

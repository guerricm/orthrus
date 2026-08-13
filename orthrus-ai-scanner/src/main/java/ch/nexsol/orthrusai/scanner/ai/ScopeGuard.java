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

import java.net.URI;

import org.springframework.stereotype.Component;

/**
 * Confines the LLM's HTTP tool to the target under test. An agent that is free to forge
 * requests must never reach a host outside the engagement scope, so every candidate URL
 * is checked against the task's target host and port before it is sent.
 */
@Component
public class ScopeGuard {

	/**
	 * Whether {@code candidateUrl} is within scope of {@code targetUrl} (same scheme host
	 * and port).
	 * @param candidateUrl the URL the agent wants to reach
	 * @param targetUrl the engagement target
	 * @return true when the candidate is on the target's host:port
	 */
	public boolean inScope(String candidateUrl, String targetUrl) {
		String candidate = hostKey(candidateUrl);
		String target = hostKey(targetUrl);
		return candidate != null && candidate.equals(target);
	}

	private String hostKey(String url) {
		if (url == null || url.isBlank()) {
			return null;
		}
		try {
			URI uri = URI.create(url.trim());
			String host = uri.getHost();
			if (host == null) {
				return null;
			}
			String scheme = (uri.getScheme() != null) ? uri.getScheme().toLowerCase() : "http";
			int port = (uri.getPort() != -1) ? uri.getPort() : defaultPort(scheme);
			return scheme + "://" + host.toLowerCase() + ":" + port;
		}
		catch (IllegalArgumentException ex) {
			return null;
		}
	}

	private int defaultPort(String scheme) {
		return "https".equals(scheme) ? 443 : 80;
	}

}

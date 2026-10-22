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

package ch.nexsol.orthrusai.scanner.config;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration for the autonomous AI scanner node. The node integrates with the orthrus
 * manager purely over the documented worker&lt;-&gt;manager HTTP contract, so these
 * properties mirror what a regular worker needs plus the AI-specific switches.
 */
@ConfigurationProperties(prefix = "orthrus")
public class AiScannerProperties {

	private final Master master = new Master();

	private final Slave slave = new Slave();

	private final Ai ai = new Ai();

	public Master getMaster() {
		return this.master;
	}

	public Slave getSlave() {
		return this.slave;
	}

	public Ai getAi() {
		return this.ai;
	}

	/**
	 * Coordinates and shared secret for reaching the manager's internal API.
	 */
	public static class Master {

		private String url = "http://localhost:8080";

		private String internalToken = "change-me-in-production";

		private long heartbeatIntervalMs = 10000;

		public String getUrl() {
			return this.url;
		}

		public void setUrl(String url) {
			this.url = url;
		}

		public String getInternalToken() {
			return this.internalToken;
		}

		public void setInternalToken(String internalToken) {
			this.internalToken = internalToken;
		}

		public long getHeartbeatIntervalMs() {
			return this.heartbeatIntervalMs;
		}

		public void setHeartbeatIntervalMs(long heartbeatIntervalMs) {
			this.heartbeatIntervalMs = heartbeatIntervalMs;
		}

	}

	/**
	 * This node's own identity as seen by the manager.
	 */
	public static class Slave {

		private String id = "orthrus-ai-scanner";

		private String advertisedUrl = "http://localhost:8091";

		public String getId() {
			return this.id;
		}

		public void setId(String id) {
			this.id = id;
		}

		public String getAdvertisedUrl() {
			return this.advertisedUrl;
		}

		public void setAdvertisedUrl(String advertisedUrl) {
			this.advertisedUrl = advertisedUrl;
		}

	}

	/**
	 * AI-specific behaviour: which families this node claims and the LLM guard-rails.
	 */
	public static class Ai {

		private boolean enabled = false;

		private List<String> families = List.of("INJECTION", "XSS", "LOGIC", "CONFIGURATION", "HTTP", "JWT", "SSL",
				"BOLA");

		private final Scanner scanner = new Scanner();

		private final Budget budget = new Budget();

		public boolean isEnabled() {
			return this.enabled;
		}

		public void setEnabled(boolean enabled) {
			this.enabled = enabled;
		}

		public List<String> getFamilies() {
			return this.families;
		}

		public void setFamilies(List<String> families) {
			this.families = families;
		}

		public Scanner getScanner() {
			return this.scanner;
		}

		public Budget getBudget() {
			return this.budget;
		}

	}

	/**
	 * LLM model selection for the scanner agents.
	 */
	public static class Scanner {

		private String model = "";

		/**
		 * Whether a reasoning model (e.g. Qwen3 on Ollama) may think before each answer.
		 * Off by default: the agent makes one model call per tool call, and the hidden
		 * reasoning multiplies the latency of every one of them.
		 */
		private boolean think = false;

		public String getModel() {
			return this.model;
		}

		public void setModel(String model) {
			this.model = model;
		}

		public boolean isThink() {
			return this.think;
		}

		public void setThink(boolean think) {
			this.think = think;
		}

	}

	/**
	 * Hard limits protecting the target and capping LLM cost per task.
	 */
	public static class Budget {

		private int maxHttpCallsPerOperation = 40;

		private int maxToolIterations = 12;

		/**
		 * How much of each probe response body is fed back to the model. The whole
		 * conversation is resent on every turn, so this bounds how fast the context
		 * grows.
		 */
		private int maxResponseChars = 1500;

		/**
		 * Time one agent may spend on one endpoint. A task's budget is derived from it
		 * and the number of endpoints, so every endpoint gets its share whatever the size
		 * of the API.
		 */
		private long endpointTimeoutSeconds = 300;

		/**
		 * Ceiling on a whole task, recon included, whatever its endpoint count.
		 */
		private long taskTimeoutSeconds = 14400;

		public int getMaxHttpCallsPerOperation() {
			return this.maxHttpCallsPerOperation;
		}

		public void setMaxHttpCallsPerOperation(int maxHttpCallsPerOperation) {
			this.maxHttpCallsPerOperation = maxHttpCallsPerOperation;
		}

		public int getMaxToolIterations() {
			return this.maxToolIterations;
		}

		public void setMaxToolIterations(int maxToolIterations) {
			this.maxToolIterations = maxToolIterations;
		}

		public int getMaxResponseChars() {
			return this.maxResponseChars;
		}

		public void setMaxResponseChars(int maxResponseChars) {
			this.maxResponseChars = maxResponseChars;
		}

		public long getEndpointTimeoutSeconds() {
			return this.endpointTimeoutSeconds;
		}

		public void setEndpointTimeoutSeconds(long endpointTimeoutSeconds) {
			this.endpointTimeoutSeconds = endpointTimeoutSeconds;
		}

		public long getTaskTimeoutSeconds() {
			return this.taskTimeoutSeconds;
		}

		public void setTaskTimeoutSeconds(long taskTimeoutSeconds) {
			this.taskTimeoutSeconds = taskTimeoutSeconds;
		}

	}

}

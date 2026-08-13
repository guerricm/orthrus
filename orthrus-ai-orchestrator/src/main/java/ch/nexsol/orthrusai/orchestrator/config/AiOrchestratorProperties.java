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

package ch.nexsol.orthrusai.orchestrator.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration for the AI orchestrator. It drives the orthrus manager's public API only,
 * so it needs the manager URL plus the LLM switches.
 */
@ConfigurationProperties(prefix = "orthrus")
public class AiOrchestratorProperties {

	private final Manager manager = new Manager();

	private final Ai ai = new Ai();

	public Manager getManager() {
		return this.manager;
	}

	public Ai getAi() {
		return this.ai;
	}

	/**
	 * The orthrus manager the orchestrator drives.
	 */
	public static class Manager {

		private String url = "http://localhost:8080";

		public String getUrl() {
			return this.url;
		}

		public void setUrl(String url) {
			this.url = url;
		}

	}

	/**
	 * LLM switches for the planning agent.
	 */
	public static class Ai {

		private boolean enabled = false;

		private final Orchestrator orchestrator = new Orchestrator();

		public boolean isEnabled() {
			return this.enabled;
		}

		public void setEnabled(boolean enabled) {
			this.enabled = enabled;
		}

		public Orchestrator getOrchestrator() {
			return this.orchestrator;
		}

	}

	/**
	 * Model selection for the planning agent.
	 */
	public static class Orchestrator {

		private String model = "";

		public String getModel() {
			return this.model;
		}

		public void setModel(String model) {
			this.model = model;
		}

	}

}

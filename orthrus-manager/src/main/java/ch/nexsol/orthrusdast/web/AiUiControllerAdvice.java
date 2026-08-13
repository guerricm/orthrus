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

package ch.nexsol.orthrusdast.web;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;

/**
 * Exposes whether AI orchestration is configured to every view, so the navigation only
 * shows the AI campaign entry when an orchestrator URL is set. Always present, unlike the
 * AI controller, so the flag is available even when the feature is off.
 */
@ControllerAdvice
public class AiUiControllerAdvice {

	private final boolean enabled;

	public AiUiControllerAdvice(@Value("${orthrus.ai.orchestrator.url:}") String orchestratorUrl) {
		this.enabled = orchestratorUrl != null && !orchestratorUrl.isBlank();
	}

	@ModelAttribute("aiOrchestrationEnabled")
	public boolean aiOrchestrationEnabled() {
		return this.enabled;
	}

}

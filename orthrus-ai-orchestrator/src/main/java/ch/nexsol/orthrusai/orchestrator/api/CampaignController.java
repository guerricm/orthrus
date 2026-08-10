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

package ch.nexsol.orthrusai.orchestrator.api;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import ch.nexsol.orthrusai.orchestrator.campaign.CampaignResult;
import ch.nexsol.orthrusai.orchestrator.campaign.CampaignService;

/**
 * Entry point of the orchestrator: an operator asks for a campaign against a target, and
 * the orchestrator plans it and launches the corresponding scan on the manager.
 */
@RestController
@RequestMapping("/api/v1/campaigns")
public class CampaignController {

	private final CampaignService campaignService;

	public CampaignController(CampaignService campaignService) {
		this.campaignService = campaignService;
	}

	@PostMapping
	public Mono<ResponseEntity<CampaignResult>> startCampaign(@RequestBody CampaignRequest request) {
		if (request.target() == null || request.target().isBlank()) {
			return Mono.just(ResponseEntity.badRequest().build());
		}
		return this.campaignService.runCampaign(request.target(), request.objective()).map(ResponseEntity::ok);
	}

	/**
	 * The campaign request from an operator.
	 *
	 * @param target the target to scan
	 * @param objective the operator's objective in natural language (optional)
	 */
	public record CampaignRequest(String target, String objective) {
	}

}

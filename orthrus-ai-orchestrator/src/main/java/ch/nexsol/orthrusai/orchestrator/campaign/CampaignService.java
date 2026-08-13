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

package ch.nexsol.orthrusai.orchestrator.campaign;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import ch.nexsol.orthrusai.orchestrator.client.OrthrusManagerClient;
import ch.nexsol.orthrusai.orchestrator.model.ScanPlan;
import ch.nexsol.orthrusai.orchestrator.plan.ScanPlanner;
import ch.nexsol.orthrusai.orchestrator.wire.ScanRequest;

/**
 * Runs one campaign: read the fleet's discoverers, ask the planner for a plan, then
 * launch the corresponding scan on the manager. Planning may block (the LLM tool-calling
 * loop), so it runs on a bounded-elastic worker; everything else stays reactive.
 */
@Service
public class CampaignService {

	private static final Logger log = LoggerFactory.getLogger(CampaignService.class);

	private final OrthrusManagerClient managerClient;

	private final ScanPlanner planner;

	public CampaignService(OrthrusManagerClient managerClient, ScanPlanner planner) {
		this.managerClient = managerClient;
		this.planner = planner;
	}

	/**
	 * Plans and launches a campaign for a target.
	 * @param target the target to scan
	 * @param objective the operator's objective (may be null)
	 * @return the campaign result
	 */
	public Mono<CampaignResult> runCampaign(String target, String objective) {
		return this.managerClient.getDiscoverers()
			.onErrorReturn(List.of())
			.flatMap((discoverers) -> Mono.fromCallable(() -> this.planner.plan(target, objective, discoverers))
				.subscribeOn(Schedulers.boundedElastic()))
			.flatMap((plan) -> launch(target, plan));
	}

	private Mono<CampaignResult> launch(String target, ScanPlan plan) {
		ScanRequest request = new ScanRequest(plan.recommendedDiscoverer(), target, List.of(), List.of(),
				plan.concurrency(), false, "en", plan.includePassed());
		log.info("Launching campaign on {} with discoverer '{}' (families {})", target, plan.recommendedDiscoverer(),
				plan.prioritizedFamilies());
		return this.managerClient.launchScan(request)
			.map((accepted) -> new CampaignResult(plan, accepted.jobId(), target, accepted.eventStreamUrl()))
			.onErrorResume((e) -> {
				log.error("Campaign launch on {} failed: {}", target, e.getMessage());
				return Mono.just(new CampaignResult(plan, null, target, null));
			});
	}

}

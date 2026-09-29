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

import java.util.List;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import ch.nexsol.orthrus.protocol.ai.Credential;
import ch.nexsol.orthrus.protocol.ai.ReconRequest;
import ch.nexsol.orthrus.protocol.ai.ReconResult;
import ch.nexsol.orthrusai.orchestrator.recon.ReconService;

/**
 * Exposes the orchestrator's shared recon: given a target, it fingerprints it once and
 * returns the endpoints and context every scanner node should work from. The manager
 * calls this when it starts an AI run, so the scanners no longer each re-probe blindly.
 */
@RestController
@RequestMapping("/api/v1/recon")
public class ReconController {

	private final ReconService reconService;

	public ReconController(ReconService reconService) {
		this.reconService = reconService;
	}

	@PostMapping
	public Mono<ResponseEntity<ReconResult>> recon(@RequestBody ReconRequest request) {
		if (request.target() == null || request.target().isBlank()) {
			return Mono.just(ResponseEntity.badRequest().build());
		}
		String host = (request.openapiOverrideHost() != null && !request.openapiOverrideHost().isBlank())
				? request.openapiOverrideHost() : null;
		List<Credential> credentials = (request.credentials() != null) ? request.credentials() : List.of();
		return this.reconService.discover(request.target(), host, credentials).map(ResponseEntity::ok);
	}

}

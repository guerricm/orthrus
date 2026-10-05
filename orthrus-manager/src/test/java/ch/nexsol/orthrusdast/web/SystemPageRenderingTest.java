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

import java.time.Instant;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.test.StepVerifier;

import ch.nexsol.orthrusdast.model.NodeStatus;
import ch.nexsol.orthrusdast.repository.SlaveNodeRepository;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The capacity column counts tasks, which hides the real load of an AI node: each task
 * runs several agents. The agent count reported by the heartbeat is stored and shown next
 * to it for AI nodes only.
 */
@SpringBootTest(properties = {
		"spring.r2dbc.url=r2dbc:h2:mem:///systempagedb;MODE=PostgreSQL;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE",
		"spring.r2dbc.username=sa", "spring.r2dbc.password=" })
@AutoConfigureWebTestClient
class SystemPageRenderingTest {

	@Autowired
	private WebTestClient webTestClient;

	@Autowired
	private SlaveNodeRepository slaveNodeRepository;

	@Test
	@WithMockUser(roles = "ADMIN")
	void anAiNodeShowsItsActiveAgentsNextToItsTasks() {
		StepVerifier.create(this.slaveNodeRepository
			.insertSlaveNode("ai-node", "http://ai-node:8091", NodeStatus.IDLE, "AI-EXECUTOR,INJECTION", Instant.now())
			.then(this.slaveNodeRepository.updateSlaveNodeUrlStatusActiveAgentsAndLastSeenAt("ai-node",
					"http://ai-node:8091", NodeStatus.IDLE.name(), 12, Instant.now()))
			.then(this.slaveNodeRepository.insertSlaveNode("worker-node", "http://worker-node:8081", NodeStatus.IDLE,
					"openapi,INJECTION", Instant.now())))
			.verifyComplete();

		String body = this.webTestClient.get()
			.uri("/system")
			.exchange()
			.expectStatus()
			.isOk()
			.expectBody(String.class)
			.returnResult()
			.getResponseBody();

		assertThat(body).contains("12 agent(s)");
		assertThat(body).as("only the AI node carries an agent badge").containsOnlyOnce("agent(s)");
	}

	@Test
	@WithMockUser(roles = "ADMIN")
	void datesAreHandedToTheBrowserAsUtcInstantsToShowInItsTimeZone() {
		StepVerifier
			.create(this.slaveNodeRepository.insertSlaveNode("tz-node", "http://tz-node:8081", NodeStatus.IDLE,
					"openapi", Instant.parse("2026-10-05T13:55:29Z")))
			.verifyComplete();

		String body = this.webTestClient.get()
			.uri("/system")
			.exchange()
			.expectStatus()
			.isOk()
			.expectBody(String.class)
			.returnResult()
			.getResponseBody();

		// The fallback text follows the server's zone (UTC in the images), so only the
		// machine-readable part is pinned.
		assertThat(body).as("UTC instant handed to the browser")
			.containsPattern("<time (?=[^>]*datetime=\"2026-10-05T13:55:29Z\")"
					+ "(?=[^>]*data-local-format=\"yyyy-MM-dd HH:mm:ss\")[^>]*>");
		assertThat(body).as("the layout script that rewrites them").contains("function localizeTimes(root)");
	}

}

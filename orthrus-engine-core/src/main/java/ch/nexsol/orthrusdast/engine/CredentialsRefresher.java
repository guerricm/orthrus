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

package ch.nexsol.orthrusdast.engine;

import java.util.List;

import reactor.core.publisher.Mono;

import ch.nexsol.orthrusdast.model.SecurityScheme;

/**
 * Issues fresh credentials for a scan whose own have stopped being accepted.
 *
 * <p>
 * OAuth2 tokens are short-lived and a long scan can outlive the token it started with,
 * which the target then answers with 401. A node that can reach the manager supplies an
 * implementation; a standalone run (the CLI) supplies none and a 401 is final.
 *
 * <p>
 * Implementations are called from several operations at once and should share one
 * in-flight request rather than minting a token per caller.
 */
@FunctionalInterface
public interface CredentialsRefresher {

	/**
	 * Issues the scan's credentials again.
	 * @return the primary scheme followed by the secondary one when there is one; empty
	 * when nothing could be issued, which makes the refused response final
	 */
	Mono<List<SecurityScheme>> refresh();

}

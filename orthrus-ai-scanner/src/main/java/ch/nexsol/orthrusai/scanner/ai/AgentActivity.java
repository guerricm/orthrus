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

import java.util.concurrent.atomic.AtomicInteger;

import org.springframework.stereotype.Component;

/**
 * Counts the family agents running on this node. A task fans out to several agents (one
 * per endpoint, a few at a time), so the task count alone hides the real load; the
 * heartbeat reports this figure next to it. An agent counts until its LLM loop returns,
 * even when its task was cancelled meanwhile, since it still holds a model slot.
 */
@Component
public class AgentActivity {

	private final AtomicInteger active = new AtomicInteger();

	public void started() {
		this.active.incrementAndGet();
	}

	public void finished() {
		this.active.decrementAndGet();
	}

	public int active() {
		return this.active.get();
	}

}

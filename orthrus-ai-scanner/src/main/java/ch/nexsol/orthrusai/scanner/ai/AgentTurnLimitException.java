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

/**
 * Thrown by a tool once the agent has used all its tool calls or its time. It is a
 * checked exception on purpose: Spring AI hands runtime exceptions from a tool back to
 * the model as an error message, which would cost one more round trip, whereas a checked
 * one aborts the tool-calling loop.
 */
public class AgentTurnLimitException extends Exception {

	public AgentTurnLimitException(int maxToolCalls) {
		this("agent stopped after its " + maxToolCalls + " allowed tool calls");
	}

	public AgentTurnLimitException(String reason) {
		super(reason);
	}

}

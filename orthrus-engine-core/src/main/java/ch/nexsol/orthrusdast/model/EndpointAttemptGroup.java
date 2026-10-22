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

package ch.nexsol.orthrusdast.model;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ch.nexsol.orthrus.protocol.node.AttemptStatus;
import ch.nexsol.orthrus.protocol.node.ScanAttempt;

/**
 * The attempts made on one endpoint, with a count per status.
 *
 * @param endpoint the method and URL of the endpoint
 * @param attempts the attempts made on it
 * @param passed attempts that found nothing
 * @param failed attempts that found a vulnerability
 * @param authError attempts not run because the credentials were rejected (401)
 * @param forbidden attempts not run because the identity lacks permission (403)
 * @param error attempts that failed to run
 * @param notRun attempts left unrun when a task spent its budget
 */
public record EndpointAttemptGroup(String endpoint, List<ScanAttempt> attempts, long passed, long failed,
		long authError, long forbidden, long error, long notRun) {

	/**
	 * Groups attempts by endpoint, keeping the order in which endpoints first appear.
	 * @param attempts the attempts of a scan
	 * @return one group per endpoint
	 */
	public static List<EndpointAttemptGroup> groupByEndpoint(List<ScanAttempt> attempts) {
		Map<String, List<ScanAttempt>> grouped = new LinkedHashMap<>();
		for (ScanAttempt a : attempts) {
			grouped.computeIfAbsent(a.operationMethod() + " " + a.operationUrl(), (k) -> new ArrayList<>()).add(a);
		}
		List<EndpointAttemptGroup> groups = new ArrayList<>();
		for (Map.Entry<String, List<ScanAttempt>> entry : grouped.entrySet()) {
			List<ScanAttempt> list = entry.getValue();
			groups.add(new EndpointAttemptGroup(entry.getKey(), list, count(list, AttemptStatus.PASSED),
					count(list, AttemptStatus.FAILED), count(list, AttemptStatus.AUTH_ERROR),
					count(list, AttemptStatus.FORBIDDEN), count(list, AttemptStatus.ERROR),
					count(list, AttemptStatus.NOT_RUN)));
		}
		return groups;
	}

	private static long count(List<ScanAttempt> attempts, AttemptStatus status) {
		return attempts.stream().filter((a) -> a.status() == status).count();
	}

}

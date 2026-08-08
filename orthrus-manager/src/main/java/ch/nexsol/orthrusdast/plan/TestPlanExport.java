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

package ch.nexsol.orthrusdast.plan;

import java.time.Instant;
import java.util.List;

import ch.nexsol.orthrusdast.model.ScanConfiguration;

/**
 * Transfer format for test plans moved between Orthrus instances.
 * <p>
 * Identifiers, timestamps and audit fields are deliberately absent: they belong to the
 * instance that produced the file, not to the plan. Secrets are replaced by
 * {@link TestPlanPortabilityService#MASK} so an export can be committed or shared.
 *
 * @param formatVersion schema version of this document
 * @param exportedAt when the document was produced
 * @param plans the exported plans
 */
public record TestPlanExport(int formatVersion, Instant exportedAt, List<Plan> plans) {

	/**
	 * Current version of the transfer format.
	 */
	public static final int CURRENT_VERSION = 1;

	/**
	 * @param name the plan name, unique within an instance
	 * @param description free-text description
	 * @param discovererId which discoverer the plan runs
	 * @param target the scanned target
	 * @param configuration the scan configuration, with secrets masked on export
	 */
	public record Plan(String name, String description, String discovererId, String target,
			ScanConfiguration configuration) {
	}

}

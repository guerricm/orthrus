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

import java.util.List;

import org.springframework.util.AntPathMatcher;

/**
 * What gateway discovery must leave out: routes by their gateway id (Spring Cloud
 * Gateway's {@code route_id}) and paths by Ant-style pattern. A pattern without wildcard
 * excludes that path and everything below it, so {@code /actuator} and
 * {@code /actuator/**} are equivalent.
 *
 * @param routeIds the route ids whose routes are not scanned
 * @param paths the path patterns that are not scanned
 */
public record GatewayExclusions(List<String> routeIds, List<String> paths) {

	private static final AntPathMatcher MATCHER = new AntPathMatcher();

	public GatewayExclusions {
		routeIds = (routeIds != null) ? List.copyOf(routeIds) : List.of();
		paths = (paths != null) ? List.copyOf(paths) : List.of();
	}

	public static GatewayExclusions none() {
		return new GatewayExclusions(List.of(), List.of());
	}

	public boolean isEmpty() {
		return this.routeIds.isEmpty() && this.paths.isEmpty();
	}

	public boolean excludesRoute(String routeId) {
		return routeId != null && this.routeIds.contains(routeId);
	}

	public boolean excludesPath(String path) {
		if (path == null || path.isEmpty()) {
			return false;
		}
		for (String pattern : this.paths) {
			if (MATCHER.isPattern(pattern) ? MATCHER.match(pattern, path) : isAtOrBelow(path, pattern)) {
				return true;
			}
		}
		return false;
	}

	private static boolean isAtOrBelow(String path, String prefix) {
		String base = prefix.endsWith("/") ? prefix.substring(0, prefix.length() - 1) : prefix;
		return path.equals(base) || path.startsWith(base + "/");
	}

}

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

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import reactor.core.publisher.Mono;

/**
 * Controller for handling custom error pages.
 */
@Controller
public class ErrorPageController {

	/**
	 * Handles 403 Forbidden errors.
	 * @return the error 403 template name
	 */
	@GetMapping("/error/403")
	public Mono<String> error403() {
		return Mono.just("error/403");
	}

	/**
	 * Handles 401 Unauthorized errors.
	 * @return the error 401 template name
	 */
	@GetMapping("/error/401")
	public Mono<String> error401() {
		return Mono.just("error/401");
	}

}

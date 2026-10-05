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

package ch.nexsol.orthrus.protocol.ai;

import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;

import static org.assertj.core.api.Assertions.assertThat;

class OpenApiEndpointsTests {

	private final ObjectMapper objectMapper = new ObjectMapper();

	@Test
	void readsPathsAndMethodsAgainstTheRelativeServerBasePath() {
		String spec = """
				{"openapi":"3.0.0","servers":[{"url":"/api/v3"}],"paths":{"/pet":{"get":{},"post":{}},"/pet/{id}":{"delete":{}}}}""";

		OpenApiEndpoints parsed = OpenApiEndpoints.parse(this.objectMapper, "https://host/api/v3/openapi.json", spec);

		assertThat(parsed.baseUrl()).isEqualTo("https://host/api/v3");
		assertThat(parsed.endpoints()).containsExactly(new Endpoint("GET", "https://host/api/v3/pet"),
				new Endpoint("POST", "https://host/api/v3/pet"),
				new Endpoint("DELETE", "https://host/api/v3/pet/{id}"));
	}

	@Test
	void honoursAnAbsoluteServerUrl() {
		String spec = """
				{"openapi":"3.0.0","servers":[{"url":"https://api.example.com/v2/"}],"paths":{"/pet":{"get":{}}}}""";

		OpenApiEndpoints parsed = OpenApiEndpoints.parse(this.objectMapper, "https://host/openapi.json", spec);

		assertThat(parsed.baseUrl()).isEqualTo("https://api.example.com/v2");
		assertThat(parsed.endpoints()).containsExactly(new Endpoint("GET", "https://api.example.com/v2/pet"));
	}

	@Test
	void fallsBackToTheDocumentParentPathWithoutServers() {
		String spec = """
				{"swagger":"2.0","paths":{"/pet":{"put":{}}}}""";

		OpenApiEndpoints parsed = OpenApiEndpoints.parse(this.objectMapper, "http://host:8080/api/v3/openapi.json",
				spec);

		assertThat(parsed.baseUrl()).isEqualTo("http://host:8080/api/v3");
		assertThat(parsed.endpoints()).containsExactly(new Endpoint("PUT", "http://host:8080/api/v3/pet"));
	}

	@Test
	void yieldsNothingForNonOpenApiOrBrokenBodies() {
		assertThat(OpenApiEndpoints.parse(this.objectMapper, "https://host/", null).endpoints()).isEmpty();
		assertThat(OpenApiEndpoints.parse(this.objectMapper, "https://host/", "<html/>").endpoints()).isEmpty();
		assertThat(OpenApiEndpoints.parse(this.objectMapper, "https://host/", "{\"paths\":{}}").endpoints()).isEmpty();
		assertThat(OpenApiEndpoints.parse(this.objectMapper, "https://host/x", "{").baseUrl())
			.isEqualTo("https://host");
	}

	@Test
	void capsTheNumberOfEndpoints() {
		StringBuilder paths = new StringBuilder();
		for (int i = 0; i < OpenApiEndpoints.MAX_ENDPOINTS + 10; i++) {
			paths.append((i > 0) ? "," : "").append("\"/p").append(i).append("\":{\"get\":{}}");
		}
		String spec = "{\"openapi\":\"3.0.0\",\"paths\":{" + paths + "}}";

		OpenApiEndpoints parsed = OpenApiEndpoints.parse(this.objectMapper, "https://host/openapi.json", spec);

		assertThat(parsed.endpoints()).hasSize(OpenApiEndpoints.MAX_ENDPOINTS);
	}

	@Test
	void rewritesTheHostKeepingPathAndQuery() {
		assertThat(OpenApiEndpoints.rewriteHost("https://old/api/pet?x=1", "new.example:8443"))
			.isEqualTo("https://new.example:8443/api/pet?x=1");
		assertThat(OpenApiEndpoints.rewriteHost("https://old/api/pet", "http://new.example/"))
			.isEqualTo("http://new.example/api/pet");
		assertThat(OpenApiEndpoints.rewriteHost("::not a url::", "new.example")).isEqualTo("::not a url::");
	}

	@Test
	void originKeepsSchemeHostAndPort() {
		assertThat(OpenApiEndpoints.origin("https://host:8443/a/b?c")).isEqualTo("https://host:8443");
		assertThat(OpenApiEndpoints.origin("http://host/")).isEqualTo("http://host");
	}

}

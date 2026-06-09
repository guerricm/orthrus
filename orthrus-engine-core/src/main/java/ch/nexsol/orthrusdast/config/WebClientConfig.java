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

package ch.nexsol.orthrusdast.config;

import java.time.Duration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.ExchangeStrategies;
import org.springframework.web.reactive.function.client.WebClient;

import reactor.netty.http.client.HttpClient;
import reactor.netty.resources.ConnectionProvider;

import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;

/**
 * WebClient configuration for the scan HTTP client.
 */
@Configuration
public class WebClientConfig {

	private final OrthrusProperties properties;

	public WebClientConfig(OrthrusProperties properties) {
		this.properties = properties;
	}

	@Bean
	public WebClient webClient() {
		int connectTimeout = properties.getHttp().getConnectTimeoutMs();
		int readTimeout = properties.getHttp().getReadTimeoutMs();
		boolean ignoreSslErrors = properties.getHttp().isIgnoreSslErrors();

		ConnectionProvider provider = ConnectionProvider.builder("orthrus-dast-pool")
			.maxConnections(500)
			.maxIdleTime(Duration.ofSeconds(20))
			.maxLifeTime(Duration.ofSeconds(60))
			.pendingAcquireTimeout(Duration.ofSeconds(30))
			.evictInBackground(Duration.ofSeconds(40))
			.build();

		HttpClient httpClient = HttpClient.create(provider)
			.responseTimeout(Duration.ofMillis(readTimeout))
			.followRedirect(true);

		if (ignoreSslErrors) {
			httpClient = httpClient.secure((spec) -> {
				try {
					spec.sslContext(
							SslContextBuilder.forClient().trustManager(InsecureTrustManagerFactory.INSTANCE).build());
				}
				catch (Exception ex) {
					throw new RuntimeException("Failed to configure insecure SSL", ex);
				}
			});
		}

		// Allow larger response bodies (up to 16MB)
		ExchangeStrategies strategies = ExchangeStrategies.builder()
			.codecs((config) -> config.defaultCodecs().maxInMemorySize(16 * 1024 * 1024))
			.build();

		return WebClient.builder()
			.clientConnector(new ReactorClientHttpConnector(httpClient))
			.exchangeStrategies(strategies)
			.build();
	}

}

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

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

@Configuration
@ConfigurationProperties(prefix = "orthrus")
@Validated
public class OrthrusProperties {

	@Valid
	private Http http = new Http();

	@Valid
	private Master master = new Master();

	@Valid
	private Slave slave = new Slave();

	@Valid
	private Discovery discovery = new Discovery();

	@Valid
	private Oast oast = new Oast();

	public Http getHttp() {
		return http;
	}

	public void setHttp(Http http) {
		this.http = http;
	}

	public Master getMaster() {
		return master;
	}

	public void setMaster(Master master) {
		this.master = master;
	}

	public Slave getSlave() {
		return slave;
	}

	public void setSlave(Slave slave) {
		this.slave = slave;
	}

	public Discovery getDiscovery() {
		return discovery;
	}

	public void setDiscovery(Discovery discovery) {
		this.discovery = discovery;
	}

	public Oast getOast() {
		return oast;
	}

	public void setOast(Oast oast) {
		this.oast = oast;
	}

	public static class Http {

		private int connectTimeoutMs = 5000;

		private int readTimeoutMs = 10000;

		private int maxRedirects = 5;

		private boolean ignoreSslErrors = false;

		/**
		 * Overall per-request budget, retries included. Must exceed readTimeoutMs plus
		 * the cumulative retry backoff, otherwise a request that is being legitimately
		 * retried is aborted before it can succeed.
		 */
		private int requestTimeoutMs = 60000;

		/**
		 * How many times a request is re-sent when the target signals a temporary
		 * condition (429, 502, 503, 504) or the connection fails.
		 */
		private int maxRetries = 4;

		/**
		 * First backoff step. Each further attempt doubles it, used as a floor when the
		 * server sends no {@code Retry-After} and capped by {@code retryMaxBackoffMs}.
		 */
		private long retryBackoffMs = 1000;

		/**
		 * Upper bound on any single backoff wait, so a large {@code Retry-After} cannot
		 * stall a scan indefinitely.
		 */
		private long retryMaxBackoffMs = 30000;

		public int getConnectTimeoutMs() {
			return connectTimeoutMs;
		}

		public void setConnectTimeoutMs(int connectTimeoutMs) {
			this.connectTimeoutMs = connectTimeoutMs;
		}

		public int getReadTimeoutMs() {
			return readTimeoutMs;
		}

		public void setReadTimeoutMs(int readTimeoutMs) {
			this.readTimeoutMs = readTimeoutMs;
		}

		public int getMaxRedirects() {
			return maxRedirects;
		}

		public void setMaxRedirects(int maxRedirects) {
			this.maxRedirects = maxRedirects;
		}

		public boolean isIgnoreSslErrors() {
			return ignoreSslErrors;
		}

		public void setIgnoreSslErrors(boolean ignoreSslErrors) {
			this.ignoreSslErrors = ignoreSslErrors;
		}

		public int getRequestTimeoutMs() {
			return requestTimeoutMs;
		}

		public void setRequestTimeoutMs(int requestTimeoutMs) {
			this.requestTimeoutMs = requestTimeoutMs;
		}

		public int getMaxRetries() {
			return maxRetries;
		}

		public void setMaxRetries(int maxRetries) {
			this.maxRetries = maxRetries;
		}

		public long getRetryBackoffMs() {
			return retryBackoffMs;
		}

		public void setRetryBackoffMs(long retryBackoffMs) {
			this.retryBackoffMs = retryBackoffMs;
		}

		public long getRetryMaxBackoffMs() {
			return retryMaxBackoffMs;
		}

		public void setRetryMaxBackoffMs(long retryMaxBackoffMs) {
			this.retryMaxBackoffMs = retryMaxBackoffMs;
		}

	}

	public static class Oast {

		/**
		 * Whether out-of-band interaction detection is enabled. When false, scanners skip
		 * OOB probing entirely instead of emitting payloads against an unreachable
		 * server.
		 */
		private boolean enabled = false;

		/**
		 * Interactsh server host used to register sessions and poll interactions (e.g.
		 * {@code oast.pro}). Required when {@link #enabled} is true.
		 */
		private String serverHost;

		/**
		 * Optional authentication token for self-hosted Interactsh servers.
		 */
		private String token;

		/**
		 * How long to poll for interactions after payloads have been sent, giving
		 * out-of-band callbacks time to arrive.
		 */
		private long pollTimeoutMs = 8000;

		public boolean isEnabled() {
			return enabled;
		}

		public void setEnabled(boolean enabled) {
			this.enabled = enabled;
		}

		public String getServerHost() {
			return serverHost;
		}

		public void setServerHost(String serverHost) {
			this.serverHost = serverHost;
		}

		public String getToken() {
			return token;
		}

		public void setToken(String token) {
			this.token = token;
		}

		public long getPollTimeoutMs() {
			return pollTimeoutMs;
		}

		public void setPollTimeoutMs(long pollTimeoutMs) {
			this.pollTimeoutMs = pollTimeoutMs;
		}

	}

	public static class Master {

		@NotBlank(message = "Master URL must be configured (orthrus.master.url)")
		private String url;

		@NotBlank(message = "Internal token must be configured (orthrus.master.internal-token)")
		private String internalToken;

		private long heartbeatIntervalMs = 10000;

		private int slaveTimeoutSeconds = 30;

		private int offlineSlaveDeletionMinutes = 15;

		/**
		 * How long to wait for a node to acknowledge a task before treating the dispatch
		 * as failed. Acknowledgement only, not execution.
		 */
		private int dispatchTimeoutMs = 10000;

		public int getDispatchTimeoutMs() {
			return dispatchTimeoutMs;
		}

		public void setDispatchTimeoutMs(int dispatchTimeoutMs) {
			this.dispatchTimeoutMs = dispatchTimeoutMs;
		}

		public String getUrl() {
			return url;
		}

		public void setUrl(String url) {
			this.url = url;
		}

		public String getInternalToken() {
			return internalToken;
		}

		public void setInternalToken(String internalToken) {
			this.internalToken = internalToken;
		}

		public long getHeartbeatIntervalMs() {
			return heartbeatIntervalMs;
		}

		public void setHeartbeatIntervalMs(long heartbeatIntervalMs) {
			this.heartbeatIntervalMs = heartbeatIntervalMs;
		}

		public int getSlaveTimeoutSeconds() {
			return slaveTimeoutSeconds;
		}

		public void setSlaveTimeoutSeconds(int slaveTimeoutSeconds) {
			this.slaveTimeoutSeconds = slaveTimeoutSeconds;
		}

		public int getOfflineSlaveDeletionMinutes() {
			return offlineSlaveDeletionMinutes;
		}

		public void setOfflineSlaveDeletionMinutes(int offlineSlaveDeletionMinutes) {
			this.offlineSlaveDeletionMinutes = offlineSlaveDeletionMinutes;
		}

	}

	public static class Slave {

		@NotBlank(message = "Slave advertised URL must be configured (orthrus.slave.advertised-url)")
		private String advertisedUrl;

		private String id;

		public String getAdvertisedUrl() {
			return advertisedUrl;
		}

		public void setAdvertisedUrl(String advertisedUrl) {
			this.advertisedUrl = advertisedUrl;
		}

		public String getId() {
			return id;
		}

		public void setId(String id) {
			this.id = id;
		}

	}

	public static class Discovery {

		private int blackboxMaxDepth = 5;

		private int blackboxTimeoutMs = 5000;

		public int getBlackboxMaxDepth() {
			return blackboxMaxDepth;
		}

		public void setBlackboxMaxDepth(int blackboxMaxDepth) {
			this.blackboxMaxDepth = blackboxMaxDepth;
		}

		public int getBlackboxTimeoutMs() {
			return blackboxTimeoutMs;
		}

		public void setBlackboxTimeoutMs(int blackboxTimeoutMs) {
			this.blackboxTimeoutMs = blackboxTimeoutMs;
		}

	}

}

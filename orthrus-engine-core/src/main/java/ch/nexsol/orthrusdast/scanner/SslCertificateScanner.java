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

package ch.nexsol.orthrusdast.scanner;

import java.net.URL;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import reactor.core.publisher.Flux;

import ch.nexsol.orthrusdast.model.CWEReference;
import ch.nexsol.orthrusdast.model.Operation;
import ch.nexsol.orthrusdast.model.RiskLevel;
import ch.nexsol.orthrusdast.model.Vulnerability;

import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;

/**
 * Scans the SSL/TLS configuration and certificate of the target. Caches the results per
 * hostname to avoid redundant connections.
 */
@Component
public class SslCertificateScanner implements SecurityScanner {

	private static final Logger log = LoggerFactory.getLogger(SslCertificateScanner.class);

	private final Set<String> scannedHosts = ConcurrentHashMap.newKeySet();

	@Override
	public String getId() {
		return "ssl-tls";
	}

	@Override
	public String getName() {
		return "SSL/TLS Configuration Scanner";
	}

	@Override
	public ScannerFamily getFamily() {
		return ScannerFamily.CONFIGURATION;
	}

	@Override
	public Flux<Vulnerability> scan(Operation operation) {
		return Flux.defer(() -> {
			if (operation.url() == null || !operation.url().toLowerCase().startsWith("https://")) {
				return Flux.empty();
			}

			try {
				URL url = new URL(operation.url());
				String hostname = url.getHost();
				int port = url.getPort() != -1 ? url.getPort() : url.getDefaultPort();
				String hostKey = hostname + ":" + port;

				// Only scan each host once
				if (!scannedHosts.add(hostKey)) {
					return Flux.empty();
				}

				log.debug("Scanning SSL/TLS for host: {}", hostKey);
				return scanHost(hostname, port, operation);

			}
			catch (Exception ex) {
				log.warn("Failed to parse URL for SSL scanning: {}", operation.url());
				return Flux.empty();
			}
		});
	}

	private Flux<Vulnerability> scanHost(String hostname, int port, Operation operation) {
		List<Vulnerability> vulnerabilities = new ArrayList<>();

		try {
			// Create a custom trust manager that trusts all certificates so we can
			// inspect them
			TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
				public X509Certificate[] getAcceptedIssuers() {
					return new X509Certificate[0];
				}

				public void checkClientTrusted(X509Certificate[] certs, String authType) {
				}

				public void checkServerTrusted(X509Certificate[] certs, String authType) {
				}
			} };

			SSLContext sc = SSLContext.getInstance("TLS");
			sc.init(null, trustAllCerts, new SecureRandom());
			SSLSocketFactory factory = sc.getSocketFactory();

			try (SSLSocket socket = (SSLSocket) factory.createSocket(hostname, port)) {
				// Ensure we attempt to use the latest protocols if available,
				// but if we want to detect old protocols, we should enable them for the
				// handshake.
				socket.setEnabledProtocols(new String[] { "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3" });
				socket.setSoTimeout(5000);
				socket.startHandshake();

				SSLSession session = socket.getSession();

				// 1. Check Protocol Version
				String protocol = session.getProtocol();
				if ("TLSv1".equals(protocol) || "TLSv1.1".equals(protocol) || "SSLv3".equals(protocol)
						|| "SSLv2".equals(protocol)) {
					vulnerabilities.add(createVulnerabilityWithTrace("Weak SSL/TLS Protocol Enabled",
							"The server is using an outdated and insecure protocol: " + protocol, RiskLevel.HIGH,
							Vulnerability.Confidence.HIGH, operation, CWEReference.CWE_319, List.of("CAPEC-97"), 7.4,
							"The negotiated protocol during handshake was " + protocol + ".",
							"Disable outdated protocols like TLS 1.0 and TLS 1.1. Enforce TLS 1.2 or TLS 1.3.",
							operation, null, "API Endpoint (Network)", "Unauthorized Access / Data Exposure"));
				}

				// 2. Check Certificate
				Certificate[] peerCerts = session.getPeerCertificates();
				if (peerCerts.length > 0 && peerCerts[0] instanceof X509Certificate cert) {

					// 2a. Expiration
					try {
						cert.checkValidity();

						// Check if expiring soon (e.g. next 30 days)
						long timeDiff = cert.getNotAfter().getTime() - System.currentTimeMillis();
						long daysLeft = TimeUnit.MILLISECONDS.toDays(timeDiff);
						if (daysLeft < 30) {
							vulnerabilities.add(createVulnerabilityWithTrace("SSL Certificate Expiring Soon",
									"The SSL certificate for " + hostname + " will expire in " + daysLeft + " days.",
									RiskLevel.LOW, Vulnerability.Confidence.HIGH, operation, CWEReference.CWE_298,
									List.of(), 3.1, "Certificate expires on " + cert.getNotAfter() + ".",
									"Renew the certificate before it expires.", operation, null,
									"API Endpoint (Network)", "Unauthorized Access / Data Exposure"));
						}
					}
					catch (CertificateExpiredException ex) {
						vulnerabilities.add(createVulnerabilityWithTrace("Expired SSL Certificate",
								"The SSL certificate for " + hostname + " has expired.", RiskLevel.HIGH,
								Vulnerability.Confidence.HIGH, operation, CWEReference.CWE_298, List.of(), 7.5,
								"Certificate expired on " + cert.getNotAfter() + ".",
								"Renew and deploy a valid SSL certificate.", operation, null, "API Endpoint (Network)",
								"Unauthorized Access / Data Exposure"));
					}
					catch (CertificateNotYetValidException ex) {
						vulnerabilities.add(createVulnerabilityWithTrace("SSL Certificate Not Yet Valid",
								"The SSL certificate for " + hostname + " is not yet valid.", RiskLevel.MEDIUM,
								Vulnerability.Confidence.HIGH, operation, CWEReference.CWE_298, List.of(), 5.3,
								"Certificate is only valid from " + cert.getNotBefore() + ".",
								"Check the system clock or deploy a valid certificate.", operation, null,
								"API Endpoint (Network)", "Unauthorized Access / Data Exposure"));
					}

					// 2b. Self-Signed
					if (cert.getIssuerX500Principal().equals(cert.getSubjectX500Principal())) {
						vulnerabilities.add(createVulnerabilityWithTrace("Self-Signed SSL Certificate",
								"The SSL certificate is self-signed, which cannot be inherently trusted by clients.",
								RiskLevel.MEDIUM, Vulnerability.Confidence.HIGH, operation, CWEReference.CWE_295,
								List.of("CAPEC-475"), 4.8, "The issuer and subject of the certificate are identical.",
								"Use a certificate signed by a trusted Certificate Authority (CA) for production environments.",
								operation, null, "API Endpoint (Network)", "Unauthorized Access / Data Exposure"));
					}

					// 2c. Weak Signature Algorithm
					String sigAlg = cert.getSigAlgName().toUpperCase();
					if (sigAlg.contains("MD5") || sigAlg.contains("SHA1")) {
						vulnerabilities.add(createVulnerabilityWithTrace("Weak Certificate Signature Algorithm",
								"The SSL certificate uses a weak signature algorithm: " + sigAlg + ".",
								RiskLevel.MEDIUM, Vulnerability.Confidence.HIGH, operation, CWEReference.CWE_327,
								List.of(), 5.9, "The certificate was signed using " + sigAlg + ".",
								"Re-issue the certificate using a strong hashing algorithm like SHA-256.", operation,
								null, "API Endpoint (Network)", "Unauthorized Access / Data Exposure"));
					}

					// 2d. Weak Key Size
					PublicKey pubKey = cert.getPublicKey();
					if (pubKey instanceof RSAPublicKey rsaPubKey) {
						int keySize = rsaPubKey.getModulus().bitLength();
						if (keySize < 2048) {
							vulnerabilities.add(createVulnerabilityWithTrace("Weak RSA Key Length",
									"The SSL certificate uses an RSA key size of " + keySize
											+ " bits, which is considered cryptographically weak.",
									RiskLevel.MEDIUM, Vulnerability.Confidence.HIGH, operation, CWEReference.CWE_200,
									List.of(), 5.9, "The RSA public key size is " + keySize + " bits.",
									"Use an RSA key size of at least 2048 bits, or switch to modern elliptic curve cryptography (ECC).",
									operation, null, "API Endpoint (Network)", "Unauthorized Access / Data Exposure"));
						}
					}

					// 2e. Hostname Mismatch
					if (!hostnameMatches(hostname, cert)) {
						vulnerabilities.add(createVulnerabilityWithTrace("Certificate Hostname Mismatch",
								"The SSL certificate presented by the server is not valid for the requested hostname ("
										+ hostname + ").",
								RiskLevel.HIGH, Vulnerability.Confidence.HIGH, operation, CWEReference.CWE_200,
								List.of("CAPEC-475"), 6.5,
								"The requested hostname '" + hostname
										+ "' does not match the CN or SANs in the certificate.",
								"Ensure the certificate is issued for the correct hostname, including any necessary Subject Alternative Names (SANs).",
								operation, null, "API Endpoint (Network)", "Unauthorized Access / Data Exposure"));
					}
				}
			}
		}
		catch (Exception ex) {
			log.warn("Failed to perform SSL scan on {}: {}", hostname, ex.getMessage());
		}

		return Flux.fromIterable(vulnerabilities);
	}

	private boolean hostnameMatches(String hostname, X509Certificate cert) {
		// Simple check against CN
		String cn = null;
		try {
			javax.naming.ldap.LdapName ldapDN = new javax.naming.ldap.LdapName(
					cert.getSubjectX500Principal().getName());
			for (javax.naming.ldap.Rdn rdn : ldapDN.getRdns()) {
				if ("CN".equalsIgnoreCase(rdn.getType())) {
					cn = rdn.getValue().toString();
					break;
				}
			}
		}
		catch (Exception ex) {
			// Ignore
		}

		if (cn != null && matchDomain(hostname, cn)) {
			return true;
		}

		// Check SANs
		try {
			Collection<List<?>> sans = cert.getSubjectAlternativeNames();
			if (sans != null) {
				for (List<?> san : sans) {
					if (san.size() >= 2 && san.get(0).equals(2)) { // type 2 is dNSName
						String dnsName = (String) san.get(1);
						if (matchDomain(hostname, dnsName)) {
							return true;
						}
					}
				}
			}
		}
		catch (CertificateParsingException ex) {
			// Ignore
		}
		return false;
	}

	private boolean matchDomain(String hostname, String pattern) {
		hostname = hostname.toLowerCase();
		pattern = pattern.toLowerCase();
		if (pattern.startsWith("*.")) {
			String suffix = pattern.substring(1); // ex.g. .example.com
			return hostname.endsWith(suffix) && hostname.indexOf('.') == hostname.length() - suffix.length();
		}
		return hostname.equals(pattern);
	}

}

package ch.hug.orthrusdast.scanner;


import ch.hug.orthrusdast.model.CWEReference;
import ch.hug.orthrusdast.model.Operation;
import ch.hug.orthrusdast.model.RiskLevel;
import ch.hug.orthrusdast.model.Vulnerability;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;

import javax.net.ssl.*;
import java.net.URL;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * Scans the SSL/TLS configuration and certificate of the target.
 * Caches the results per hostname to avoid redundant connections.
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
    public Flux<Vulnerability> scan(Operation operation) {
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

        } catch (Exception e) {
            log.warn("Failed to parse URL for SSL scanning: {}", operation.url());
            return Flux.empty();
        }
    }

    private Flux<Vulnerability> scanHost(String hostname, int port, Operation operation) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        try {
            // Create a custom trust manager that trusts all certificates so we can inspect them
            TrustManager[] trustAllCerts = new TrustManager[]{
                    new X509TrustManager() {
                        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                        public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                        public void checkServerTrusted(X509Certificate[] certs, String authType) { }
                    }
            };

            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            SSLSocketFactory factory = sc.getSocketFactory();

            try (SSLSocket socket = (SSLSocket) factory.createSocket(hostname, port)) {
                // Ensure we attempt to use the latest protocols if available, 
                // but if we want to detect old protocols, we should enable them for the handshake.
                socket.setEnabledProtocols(new String[]{"TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"});
                socket.setSoTimeout(5000);
                socket.startHandshake();

                SSLSession session = socket.getSession();
                
                // 1. Check Protocol Version
                String protocol = session.getProtocol();
                if ("TLSv1".equals(protocol) || "TLSv1.1".equals(protocol) || "SSLv3".equals(protocol) || "SSLv2".equals(protocol)) {
                    vulnerabilities.add(Vulnerability.createWithDetails(
                            "Weak SSL/TLS Protocol Enabled",
                            "The server is using an outdated and insecure protocol: " + protocol,
                            RiskLevel.HIGH,
                            Vulnerability.Confidence.HIGH,
                            getId(),
                            operation,
                            CWEReference.CWE_319,
                            List.of("CAPEC-97"),
                            7.4,
                            "The negotiated protocol during handshake was " + protocol + ".",
                            "Disable outdated protocols like TLS 1.0 and TLS 1.1. Enforce TLS 1.2 or TLS 1.3.",
                            "Initiated a TLS handshake with " + hostname,
                            "Negotiated Protocol: " + protocol
                    ,
                                    "API Endpoint (Network)",
                                    "Unauthorized Access / Data Exposure"));
                }

                // 2. Check Certificate
                java.security.cert.Certificate[] peerCerts = session.getPeerCertificates();
                if (peerCerts.length > 0 && peerCerts[0] instanceof X509Certificate cert) {

                    // 2a. Expiration
                    try {
                        cert.checkValidity();
                        
                        // Check if expiring soon (e.g. next 30 days)
                        long timeDiff = cert.getNotAfter().getTime() - System.currentTimeMillis();
                        long daysLeft = TimeUnit.MILLISECONDS.toDays(timeDiff);
                        if (daysLeft < 30) {
                            vulnerabilities.add(Vulnerability.createWithDetails(
                                    "SSL Certificate Expiring Soon",
                                    "The SSL certificate for " + hostname + " will expire in " + daysLeft + " days.",
                                    RiskLevel.LOW,
                                    Vulnerability.Confidence.HIGH,
                                    getId(),
                                    operation,
                                    CWEReference.CWE_298,
                                    List.of(),
                                    3.1,
                                    "Certificate expires on " + cert.getNotAfter() + ".",
                                    "Renew the certificate before it expires.",
                                    "Analyzed the certificate payload.",
                                    "Not After: " + cert.getNotAfter()
                            ,
                                    "API Endpoint (Network)",
                                    "Unauthorized Access / Data Exposure"));
                        }
                    } catch (CertificateExpiredException e) {
                        vulnerabilities.add(Vulnerability.createWithDetails(
                                "Expired SSL Certificate",
                                "The SSL certificate for " + hostname + " has expired.",
                                RiskLevel.HIGH,
                                Vulnerability.Confidence.HIGH,
                                getId(),
                                operation,
                                CWEReference.CWE_298,
                                List.of(),
                                7.5,
                                "Certificate expired on " + cert.getNotAfter() + ".",
                                "Renew and deploy a valid SSL certificate.",
                                "Analyzed the certificate payload.",
                                "Not After: " + cert.getNotAfter()
                        ,
                                    "API Endpoint (Network)",
                                    "Unauthorized Access / Data Exposure"));
                    } catch (CertificateNotYetValidException e) {
                        vulnerabilities.add(Vulnerability.createWithDetails(
                                "SSL Certificate Not Yet Valid",
                                "The SSL certificate for " + hostname + " is not yet valid.",
                                RiskLevel.MEDIUM,
                                Vulnerability.Confidence.HIGH,
                                getId(),
                                operation,
                                CWEReference.CWE_298,
                                List.of(),
                                5.3,
                                "Certificate is only valid from " + cert.getNotBefore() + ".",
                                "Check the system clock or deploy a valid certificate.",
                                "Analyzed the certificate payload.",
                                "Not Before: " + cert.getNotBefore()
                        ,
                                    "API Endpoint (Network)",
                                    "Unauthorized Access / Data Exposure"));
                    }

                    // 2b. Self-Signed
                    if (cert.getIssuerX500Principal().equals(cert.getSubjectX500Principal())) {
                        vulnerabilities.add(Vulnerability.createWithDetails(
                                "Self-Signed SSL Certificate",
                                "The SSL certificate is self-signed, which cannot be inherently trusted by clients.",
                                RiskLevel.MEDIUM,
                                Vulnerability.Confidence.HIGH,
                                getId(),
                                operation,
                                CWEReference.CWE_295,
                                List.of("CAPEC-475"),
                                4.8,
                                "The issuer and subject of the certificate are identical.",
                                "Use a certificate signed by a trusted Certificate Authority (CA) for production environments.",
                                "Analyzed the certificate payload.",
                                "Issuer: " + cert.getIssuerX500Principal().getName()
                        ,
                                    "API Endpoint (Network)",
                                    "Unauthorized Access / Data Exposure"));
                    }

                    // 2c. Weak Signature Algorithm
                    String sigAlg = cert.getSigAlgName().toUpperCase();
                    if (sigAlg.contains("MD5") || sigAlg.contains("SHA1")) {
                        vulnerabilities.add(Vulnerability.createWithDetails(
                                "Weak Certificate Signature Algorithm",
                                "The SSL certificate uses a weak signature algorithm: " + sigAlg + ".",
                                RiskLevel.MEDIUM,
                                Vulnerability.Confidence.HIGH,
                                getId(),
                                operation,
                                CWEReference.CWE_327,
                                List.of(),
                                5.9,
                                "The certificate was signed using " + sigAlg + ".",
                                "Re-issue the certificate using a strong hashing algorithm like SHA-256.",
                                "Analyzed the certificate payload.",
                                "Signature Algorithm: " + sigAlg
                        ,
                                    "API Endpoint (Network)",
                                    "Unauthorized Access / Data Exposure"));
                    }
                }
            }
        } catch (Exception e) {
            log.warn("Failed to perform SSL scan on {}: {}", hostname, e.getMessage());
        }

        return Flux.fromIterable(vulnerabilities);
    }
}

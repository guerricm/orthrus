package ch.nexsol.orthrusdast.model;

/**
 * Represents the OWASP Top 10 vulnerability categories.
 * Using the actual OWASP Top 10:2025 draft formatting.
 */
public enum OwaspReference {
    A01_BROKEN_ACCESS_CONTROL("A01:2025", "Broken Access Control"),
    A02_SECURITY_MISCONFIGURATION("A02:2025", "Security Misconfiguration"),
    A03_SUPPLY_CHAIN_FAILURES("A03:2025", "Software Supply Chain Failures"),
    A04_CRYPTOGRAPHIC_FAILURES("A04:2025", "Cryptographic Failures"),
    A05_INJECTION("A05:2025", "Injection"),
    A06_INSECURE_DESIGN("A06:2025", "Insecure Design"),
    A07_AUTH_FAILURES("A07:2025", "Authentication Failures"),
    A08_INTEGRITY_FAILURES("A08:2025", "Software or Data Integrity Failures"),
    A09_LOGGING_FAILURES("A09:2025", "Security Logging and Alerting Failures"),
    A10_EXCEPTIONAL_CONDITIONS("A10:2025", "Mishandling of Exceptional Conditions"),
    OTHER("Other", "Other / Uncategorized");

    private final String code;
    private final String name;

    OwaspReference(String code, String name) {
        this.code = code;
        this.name = name;
    }

    public String getCode() {
        return code;
    }

    public String getName() {
        return name;
    }
}

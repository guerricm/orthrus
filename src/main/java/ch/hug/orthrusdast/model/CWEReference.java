package ch.hug.orthrusdast.model;

/**
 * CWE (Common Weakness Enumeration) references for detected vulnerabilities.
 * Extended to cover all scanner categories.
 */
public enum CWEReference {
    // Input Validation
    CWE_20("Improper Input Validation", 20),

    // XSS
    CWE_79("Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')", 79),

    // Path Traversal
    CWE_22("Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')", 22),

    // OS Command Injection
    CWE_78("Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')", 78),

    // SQL / NoSQL / Template / Generic Injection
    CWE_74("Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')", 74),
    CWE_89("Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')", 89),
    CWE_943("Improper Neutralization of Special Elements in Data Query Logic", 943),
    CWE_1336("Improper Neutralization of Special Elements Used in a Template Engine", 1336),

    // Authentication
    CWE_287("Improper Authentication", 287),
    CWE_306("Missing Authentication for Critical Function", 306),
    CWE_521("Weak Password Requirements", 521),

    // CSRF
    CWE_352("Cross-Site Request Forgery (CSRF)", 352),

    // Security Misconfiguration
    CWE_16("Configuration", 16),
    CWE_611("Improper Restriction of XML External Entity Reference", 611),

    // CORS
    CWE_346("Origin Validation Error", 346),
    CWE_942("Permissive Cross-domain Policy with Untrusted Domains", 942),

    // SSRF
    CWE_918("Server-Side Request Forgery (SSRF)", 918),

    // Broken Access Control / BOLA / BOPLA
    CWE_639("Authorization Bypass Through User-Controlled Key", 639),
    CWE_915("Improperly Controlled Modification of Dynamically-Determined Object Attributes ('Mass Assignment')", 915),

    // Cryptographic Failures & Transmission
    CWE_295("Improper Certificate Validation", 295),
    CWE_298("Improper Validation of Certificate Expiration", 298),
    CWE_319("Cleartext Transmission of Sensitive Information", 319),
    CWE_327("Use of a Broken or Risky Cryptographic Algorithm", 327),
    CWE_347("Improper Verification of Cryptographic Signature", 347),

    // Security Headers & Cookies
    CWE_693("Protection Mechanism Failure", 693),
    CWE_614("Sensitive Cookie in HTTPS Session Without 'Secure' Attribute", 614),
    CWE_1004("Sensitive Cookie Without 'HttpOnly' Flag", 1004),
    CWE_1275("Sensitive Cookie with Improper SameSite Attribute", 1275),
    CWE_1021("Improper Restriction of Rendered UI Layers or Frames", 1021),

    // Rate Limiting & Resource Consumption
    CWE_307("Improper Restriction of Excessive Authentication Attempts", 307),
    CWE_400("Uncontrolled Resource Consumption", 400),
    CWE_799("Improper Control of Interaction Frequency", 799),

    // Information Exposure & Verbose Errors
    CWE_200("Exposure of Sensitive Information to an Unauthorized Actor", 200),
    CWE_209("Generation of Error Message Containing Sensitive Information", 209),

    // Open Redirect
    CWE_601("URL Redirection to Untrusted Site ('Open Redirect')", 601),

    // HTTP Method Tampering
    CWE_650("Trusting HTTP Permission Methods on the Server Side", 650),

    // Data handling & Deserialization
    CWE_434("Unrestricted Upload of File with Dangerous Type", 434),
    CWE_502("Deserialization of Untrusted Data", 502),
    CWE_913("Improper Control of Dynamically-Managed Code Resources", 913);

    private final String name;
    private final int id;

    CWEReference(String name, int id) {
        this.name = name;
        this.id = id;
    }

    public String getName() { return name; }
    public int getId() { return id; }

    public String getCweId() {
        return "CWE-" + id;
    }
}

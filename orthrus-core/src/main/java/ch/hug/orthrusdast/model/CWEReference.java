package ch.hug.orthrusdast.model;

/**
 * CWE (Common Weakness Enumeration) references for detected vulnerabilities.
 * Extended to cover all scanner categories and map directly to OWASP Top 10 (2025).
 */
public enum CWEReference {
    // Input Validation
    CWE_20("Improper Input Validation", 20, OwaspReference.A05_INJECTION),

    // XSS
    CWE_79("Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')", 79, OwaspReference.A05_INJECTION),

    // Path Traversal
    CWE_22("Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')", 22, OwaspReference.A01_BROKEN_ACCESS_CONTROL),

    // OS Command Injection
    CWE_78("Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')", 78, OwaspReference.A05_INJECTION),

    // SQL / NoSQL / Template / Generic Injection
    CWE_74("Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')", 74, OwaspReference.A05_INJECTION),
    CWE_89("Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')", 89, OwaspReference.A05_INJECTION),
    CWE_94("Improper Control of Generation of Code ('Code Injection')", 94, OwaspReference.A05_INJECTION),
    CWE_444("Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling')", 444, OwaspReference.A06_INSECURE_DESIGN),
    CWE_943("Improper Neutralization of Special Elements in Data Query Logic", 943, OwaspReference.A05_INJECTION),
    CWE_1336("Improper Neutralization of Special Elements Used in a Template Engine", 1336, OwaspReference.A05_INJECTION),

    // Authentication
    CWE_287("Improper Authentication", 287, OwaspReference.A07_AUTH_FAILURES),
    CWE_306("Missing Authentication for Critical Function", 306, OwaspReference.A07_AUTH_FAILURES),
    CWE_521("Weak Password Requirements", 521, OwaspReference.A07_AUTH_FAILURES),

    // CSRF
    CWE_352("Cross-Site Request Forgery (CSRF)", 352, OwaspReference.A01_BROKEN_ACCESS_CONTROL),

    // Security Misconfiguration
    CWE_16("Configuration", 16, OwaspReference.A02_SECURITY_MISCONFIGURATION),
    CWE_611("Improper Restriction of XML External Entity Reference", 611, OwaspReference.A02_SECURITY_MISCONFIGURATION),

    // CORS
    CWE_346("Origin Validation Error", 346, OwaspReference.A02_SECURITY_MISCONFIGURATION),
    CWE_942("Permissive Cross-domain Policy with Untrusted Domains", 942, OwaspReference.A02_SECURITY_MISCONFIGURATION),

    // SSRF
    CWE_918("Server-Side Request Forgery (SSRF)", 918, OwaspReference.A06_INSECURE_DESIGN),

    // Broken Access Control / BOLA / BOPLA / BFLA
    CWE_285("Improper Authorization", 285, OwaspReference.A01_BROKEN_ACCESS_CONTROL),
    CWE_639("Authorization Bypass Through User-Controlled Key", 639, OwaspReference.A01_BROKEN_ACCESS_CONTROL),
    CWE_915("Improperly Controlled Modification of Dynamically-Determined Object Attributes ('Mass Assignment')", 915, OwaspReference.A08_INTEGRITY_FAILURES),

    // Cryptographic Failures & Transmission
    CWE_295("Improper Certificate Validation", 295, OwaspReference.A04_CRYPTOGRAPHIC_FAILURES),
    CWE_298("Improper Validation of Certificate Expiration", 298, OwaspReference.A04_CRYPTOGRAPHIC_FAILURES),
    CWE_319("Cleartext Transmission of Sensitive Information", 319, OwaspReference.A04_CRYPTOGRAPHIC_FAILURES),
    CWE_327("Use of a Broken or Risky Cryptographic Algorithm", 327, OwaspReference.A04_CRYPTOGRAPHIC_FAILURES),
    CWE_347("Improper Verification of Cryptographic Signature", 347, OwaspReference.A04_CRYPTOGRAPHIC_FAILURES),

    // Security Headers & Cookies
    CWE_693("Protection Mechanism Failure", 693, OwaspReference.A02_SECURITY_MISCONFIGURATION),
    CWE_614("Sensitive Cookie in HTTPS Session Without 'Secure' Attribute", 614, OwaspReference.A02_SECURITY_MISCONFIGURATION),
    CWE_1004("Sensitive Cookie Without 'HttpOnly' Flag", 1004, OwaspReference.A02_SECURITY_MISCONFIGURATION),
    CWE_1275("Sensitive Cookie with Improper SameSite Attribute", 1275, OwaspReference.A02_SECURITY_MISCONFIGURATION),
    CWE_1021("Improper Restriction of Rendered UI Layers or Frames", 1021, OwaspReference.A02_SECURITY_MISCONFIGURATION),

    // Rate Limiting & Resource Consumption
    CWE_307("Improper Restriction of Excessive Authentication Attempts", 307, OwaspReference.A07_AUTH_FAILURES),
    CWE_400("Uncontrolled Resource Consumption", 400, OwaspReference.A06_INSECURE_DESIGN),
    CWE_770("Allocation of Resources Without Limits or Throttling", 770, OwaspReference.A06_INSECURE_DESIGN),
    CWE_799("Improper Control of Interaction Frequency", 799, OwaspReference.A06_INSECURE_DESIGN),

    // Information Exposure & Verbose Errors
    CWE_200("Exposure of Sensitive Information to an Unauthorized Actor", 200, OwaspReference.OTHER),
    CWE_209("Generation of Error Message Containing Sensitive Information", 209, OwaspReference.A02_SECURITY_MISCONFIGURATION),
    CWE_598("Information Exposure Through Query Strings in GET Request", 598, OwaspReference.A04_CRYPTOGRAPHIC_FAILURES),

    // Open Redirect
    CWE_601("URL Redirection to Untrusted Site ('Open Redirect')", 601, OwaspReference.A01_BROKEN_ACCESS_CONTROL),

    // HTTP Method Tampering
    CWE_650("Trusting HTTP Permission Methods on the Server Side", 650, OwaspReference.A02_SECURITY_MISCONFIGURATION),

    // Data handling & Deserialization
    CWE_434("Unrestricted Upload of File with Dangerous Type", 434, OwaspReference.A06_INSECURE_DESIGN),
    CWE_502("Deserialization of Untrusted Data", 502, OwaspReference.A08_INTEGRITY_FAILURES),
    CWE_913("Improper Control of Dynamically-Managed Code Resources", 913, OwaspReference.A08_INTEGRITY_FAILURES);

    private final String name;
    private final int id;
    private final OwaspReference owaspCategory;

    CWEReference(String name, int id, OwaspReference owaspCategory) {
        this.name = name;
        this.id = id;
        this.owaspCategory = owaspCategory;
    }

    public String getName() { return name; }
    public int getId() { return id; }
    
    public String getCweId() {
        return "CWE-" + id;
    }
    
    public OwaspReference getOwaspCategory() {
        return owaspCategory;
    }
}

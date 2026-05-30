package ch.hug.orthrusdast.scanner;

import ch.hug.orthrusdast.http.ScanHttpClient;
import ch.hug.orthrusdast.model.CWEReference;
import ch.hug.orthrusdast.model.Operation;
import ch.hug.orthrusdast.model.RiskLevel;
import ch.hug.orthrusdast.model.Vulnerability;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;

import java.util.List;

/**
 * Scans for Unrestricted File Upload vulnerabilities (CWE-434).
 */
@Component
public class FileUploadScanner implements SecurityScanner {

    private final ScanHttpClient httpClient;
    
    // Minimal malicious file payload (EICAR standard antivirus test string)
    private static final String EICAR_PAYLOAD = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    public FileUploadScanner(ScanHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public String getId() {
        return "file-upload";
    }

    @Override
    public String getName() {
        return "Unrestricted File Upload Scanner";
    }

    @Override
    public Flux<Vulnerability> scan(Operation operation) {
        // Only target endpoints that likely accept multipart/form-data
        if (!List.of("POST", "PUT").contains(operation.method().toUpperCase())) {
            return Flux.empty();
        }

        // We could also check operation.expectedContentTypes() for multipart/form-data
        // but it's safe to test all POSTs if they accept arbitrary data.
        
        // Simulating a multipart upload of a dangerous file
        String boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW";
        String multipartBody = "--" + boundary + "\r\n" +
                "Content-Disposition: form-data; name=\"file\"; filename=\"eicar.com\"\r\n" +
                "Content-Type: application/x-msdownload\r\n\r\n" +
                EICAR_PAYLOAD + "\r\n" +
                "--" + boundary + "--\r\n";

        java.util.Map<String, String> newHeaders = new java.util.HashMap<>(operation.headers());
        newHeaders.put("Content-Type", "multipart/form-data; boundary=" + boundary);

        Operation testOp = new Operation(
                operation.url(),
                operation.method(),
                newHeaders,
                operation.queryParams(),
                multipartBody,
                operation.securityRequirements(),
                operation.expectedContentTypes(),
                operation.authScheme()
        );

        return httpClient.send(testOp).flatMapMany(response -> {
            // If the server accepts the file (2xx) and it contains the dangerous payload or we get a success message
            if (response.isSuccessful()) {
                Vulnerability vuln = Vulnerability.createWithDetails(
                        "Unrestricted File Upload",
                        "The endpoint allowed the upload of an executable or potentially dangerous file (EICAR test string) without blocking it.",
                        RiskLevel.HIGH,
                        Vulnerability.Confidence.MEDIUM,
                        getId(),
                        operation,
                        CWEReference.CWE_434,
                        "Insecure Design",
                        List.of("CAPEC-17"),
                        8.8,
                        "Server responded with " + response.statusCode() + " OK after uploading an EICAR test file.",
                        "Implement strict file type validation (using magic bytes, not just extensions). Use an antivirus scanner on all uploaded files. Store files outside the web root.",
                        "Uploaded a multipart/form-data file named eicar.com containing the EICAR test string.",
                        "Response status: " + response.statusCode()
                );
                return Flux.just(vuln);
            }
            return Flux.empty();
        });
    }
}

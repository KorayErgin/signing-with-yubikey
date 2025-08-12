package main;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api")
public class VerifyController {
    private final CertificateService certificateService;
    private final VerifyService verifyService;

    public VerifyController(CertificateService certificateService, VerifyService verifyService) {
        this.certificateService = certificateService;
        this.verifyService = verifyService;
    }

    // --- 1) Registration: kullanıcı → sertifika PEM kaydı ---
    @PostMapping("/register-key")
    public ResponseEntity<?> register(@RequestBody Map<String, String> req) throws Exception {
        String userId = req.get("userId");
        String certificatePem = req.get("certificatePem");
        if (userId == null || certificatePem == null) return ResponseEntity.badRequest().body(Map.of("error", "userId ve certificatePem gerekli"));
        UserKey uk = certificateService.registerKey(userId, certificatePem);
        return ResponseEntity.ok(Map.of(
                "userId", uk.getUserId(),
                "fingerprint", uk.getFingerprint(),
                "publicKeyAlgorithm", uk.getPublicKeyAlgorithm()
        ));
    }

    // --- 2) Verification: imzanın doğrulanması ---
    @PostMapping("/verify")
    public ResponseEntity<?> verify(@RequestBody Map<String, String> req) throws Exception {
        String userId = req.get("userId");
        String message = req.get("message");
        String signatureB64 = req.get("signatureBase64");
        if (userId == null || message == null || signatureB64 == null)
            return ResponseEntity.badRequest().body(Map.of("error", "userId, message, signatureBase64 gerekli"));
        boolean ok = verifyService.verify(userId, message, signatureB64);
        return ResponseEntity.ok(Map.of("verified", ok));
    }

    // --- 3) (Opsiyonel) Fingerprint ile doğrula ---
    @PostMapping("/verify/by-fingerprint")
    public ResponseEntity<?> verifyByFp(@RequestBody Map<String, String> req) throws Exception {
        String userId = req.get("userId");
        String fingerprint = req.get("fingerprint");
        String message = req.get("message");
        String signatureB64 = req.get("signatureBase64");
        if (userId == null || fingerprint == null || message == null || signatureB64 == null)
            return ResponseEntity.badRequest().body(Map.of("error", "userId, fingerprint, message, signatureBase64 gerekli"));
        boolean ok = verifyService.verifyWithFingerprint(userId, fingerprint, message, signatureB64);
        return ResponseEntity.ok(Map.of("verified", ok));
    }
}

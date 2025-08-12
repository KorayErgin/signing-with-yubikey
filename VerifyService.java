package main;


import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Base64;

@Service
public class VerifyService {
    private final UserKeyRepository repo;
    public VerifyService(UserKeyRepository repo) { this.repo = repo; }

    /** Kayıtlı (revoked=false) son anahtarla doğrular. */
    public boolean verify(String userId, String message, String signatureB64) throws Exception {
        UserKey uk = repo.findFirstByUserIdAndRevokedOrderByCreatedAtDesc(userId, false)
                .orElseThrow(() -> new IllegalArgumentException("Kullanıcı için kayıtlı anahtar yok"));
        return verifyWithCertPem(uk.getCertificatePem(), message, signatureB64);
    }

    /** Spesifik fingerprint ile doğrulama (opsiyonel). */
    public boolean verifyWithFingerprint(String userId, String fingerprint, String message, String sigB64) throws Exception {
        UserKey uk = repo.findByUserIdAndFingerprint(userId, fingerprint)
                .orElseThrow(() -> new IllegalArgumentException("Fingerprint bulunamadı"));
        if (uk.isRevoked()) throw new IllegalStateException("Anahtar revoked");
        return verifyWithCertPem(uk.getCertificatePem(), message, sigB64);
    }

    private boolean verifyWithCertPem(String certificatePem, String message, String signatureB64) throws Exception {
        X509Certificate cert = PemUtils.readX509FromPem(certificatePem);
        String alg = cert.getPublicKey().getAlgorithm(); // RSA veya EC
        String jca;
        if ("RSA".equalsIgnoreCase(alg)) {
            jca = "SHA256withRSA";
        } else if ("EC".equalsIgnoreCase(alg) || "ECDSA".equalsIgnoreCase(alg)) {
            jca = "SHA256withECDSA"; // P-256 varsayılan; P-384 ise SHA384withECDSA seçebilirsin
        } else {
            throw new IllegalArgumentException("Desteklenmeyen public key alg: " + alg);
        }
        Signature s = Signature.getInstance(jca);
        s.initVerify(cert.getPublicKey());
        s.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] sig = Base64.getDecoder().decode(signatureB64);
        return s.verify(sig);
    }
}

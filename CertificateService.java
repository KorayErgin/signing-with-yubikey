package main;
import org.springframework.stereotype.Service;

import java.security.PublicKey;
import java.security.cert.X509Certificate;

@Service
public class CertificateService {
    private final UserKeyRepository repo;
    public CertificateService(UserKeyRepository repo) { this.repo = repo; }

    /** Kullanıcı için sertifikayı kayıt eder veya günceller. */
    public UserKey registerKey(String userId, String certificatePem) throws Exception {
        X509Certificate cert = PemUtils.readX509FromPem(certificatePem);
        String fpr = PemUtils.sha256FingerprintHex(cert.getEncoded());
        PublicKey pk = cert.getPublicKey();

        UserKey uk = repo.findByUserIdAndFingerprint(userId, fpr).orElse(new UserKey());
        uk.setUserId(userId);
        uk.setFingerprint(fpr);
        uk.setCertificatePem(certificatePem.trim());
        uk.setPublicKeyAlgorithm(pk.getAlgorithm()); // RSA veya EC
        return repo.save(uk);
    }
}

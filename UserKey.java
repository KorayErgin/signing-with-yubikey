package main;



import jakarta.persistence.*;
        import java.time.OffsetDateTime;

@Entity
@Table(name = "user_keys", indexes = {
        @Index(name = "uk_user_fpr", columnList = "userId,fingerprint", unique = true)
})
public class UserKey {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String userId;              // Uygulamadaki kullanıcı ID

    @Column(nullable = false, length = 128)
    private String fingerprint;         // SHA-256 parmak izi (hex)

    @Lob
    @Column(nullable = false)
    private String certificatePem;      // PEM X.509 sertifika

    @Column(nullable = false)
    private String publicKeyAlgorithm;  // RSA veya EC

    @Column(nullable = false)
    private OffsetDateTime createdAt = OffsetDateTime.now();

    @Column(nullable = false)
    private boolean revoked = false;

    public Long getId() { return id; }
    public String getUserId() { return userId; }
    public void setUserId(String userId) { this.userId = userId; }
    public String getFingerprint() { return fingerprint; }
    public void setFingerprint(String fingerprint) { this.fingerprint = fingerprint; }
    public String getCertificatePem() { return certificatePem; }
    public void setCertificatePem(String certificatePem) { this.certificatePem = certificatePem; }
    public String getPublicKeyAlgorithm() { return publicKeyAlgorithm; }
    public void setPublicKeyAlgorithm(String publicKeyAlgorithm) { this.publicKeyAlgorithm = publicKeyAlgorithm; }
    public OffsetDateTime getCreatedAt() { return createdAt; }
    public boolean isRevoked() { return revoked; }
    public void setRevoked(boolean revoked) { this.revoked = revoked; }
}

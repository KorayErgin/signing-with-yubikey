package main;


import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface UserKeyRepository extends JpaRepository<UserKey, Long> {
    Optional<UserKey> findFirstByUserIdAndRevokedOrderByCreatedAtDesc(String userId, boolean revoked);
    Optional<UserKey> findByUserIdAndFingerprint(String userId, String fingerprint);
    List<UserKey> findAllByUserIdAndRevoked(String userId, boolean revoked);
}
package com.innowise.authservice.repository;

import com.innowise.authservice.TestcontainersConfiguration;
import com.innowise.authservice.config.JpaAuditingConfig;
import com.innowise.authservice.model.RefreshToken;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.context.annotation.Import;

import java.time.LocalDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import({TestcontainersConfiguration.class, JpaAuditingConfig.class})
class RefreshTokenRepositoryTest {

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Test
    void findByTokenHash_shouldReturnSavedToken() {
        RefreshToken token = new RefreshToken();
        token.setTokenHash("sha256hash_abc123");
        token.setUserId(10L);
        token.setExpiresAt(LocalDateTime.now().plusDays(7));
        refreshTokenRepository.save(token);

        RefreshToken found = refreshTokenRepository.findByTokenHash("sha256hash_abc123").orElseThrow();

        assertThat(found.getTokenHash()).isEqualTo("sha256hash_abc123");
        assertThat(found.getUserId()).isEqualTo(10L);
    }

    @Test
    void deleteAllByUserId_shouldRemoveAllTokensForUser() {
        RefreshToken t1 = new RefreshToken();
        t1.setTokenHash("hash_session1");
        t1.setUserId(20L);
        t1.setExpiresAt(LocalDateTime.now().plusDays(7));

        RefreshToken t2 = new RefreshToken();
        t2.setTokenHash("hash_session2");
        t2.setUserId(20L);
        t2.setExpiresAt(LocalDateTime.now().plusDays(7));

        refreshTokenRepository.saveAll(List.of(t1, t2));

        refreshTokenRepository.deleteAllByUserId(20L);

        assertThat(refreshTokenRepository.findByTokenHash("hash_session1")).isEmpty();
        assertThat(refreshTokenRepository.findByTokenHash("hash_session2")).isEmpty();
    }

    @Test
    void deleteByTokenHash_shouldRemoveOnlyMatchingToken() {
        RefreshToken target = new RefreshToken();
        target.setTokenHash("hash_to_delete");
        target.setUserId(30L);
        target.setExpiresAt(LocalDateTime.now().plusDays(7));

        RefreshToken other = new RefreshToken();
        other.setTokenHash("hash_to_keep");
        other.setUserId(30L);
        other.setExpiresAt(LocalDateTime.now().plusDays(7));

        refreshTokenRepository.saveAll(List.of(target, other));

        refreshTokenRepository.deleteByTokenHash("hash_to_delete");

        assertThat(refreshTokenRepository.findByTokenHash("hash_to_delete")).isEmpty();
        assertThat(refreshTokenRepository.findByTokenHash("hash_to_keep")).isPresent();
    }

    @Test
    void createdAt_shouldBePopulatedOnSave() {
        RefreshToken token = new RefreshToken();
        token.setTokenHash("hash_audit");
        token.setUserId(40L);
        token.setExpiresAt(LocalDateTime.now().plusDays(7));
        refreshTokenRepository.save(token);

        RefreshToken found = refreshTokenRepository.findByTokenHash("hash_audit").orElseThrow();

        assertThat(found.getCreatedAt()).isNotNull();
    }
}

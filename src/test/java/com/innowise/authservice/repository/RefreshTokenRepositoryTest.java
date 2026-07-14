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
import static org.assertj.core.api.Assertions.assertThatCode;

@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import({TestcontainersConfiguration.class, JpaAuditingConfig.class})
class RefreshTokenRepositoryTest {

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    private RefreshToken createRefreshToken(String hash, Long userId) {
        RefreshToken t = new RefreshToken();
        t.setTokenHash(hash);
        t.setUserId(userId);
        t.setExpiresAt(LocalDateTime.now().plusDays(7));
        return t;
    }

    @Test
    void findByTokenHash_shouldReturnSavedToken() {
        refreshTokenRepository.save(createRefreshToken("sha256hash_abc123", 10L));

        RefreshToken found = refreshTokenRepository.findByTokenHash("sha256hash_abc123").orElseThrow();

        assertThat(found.getTokenHash()).isEqualTo("sha256hash_abc123");
        assertThat(found.getUserId()).isEqualTo(10L);
        assertThat(found.getExpiresAt()).isNotNull();
    }

    @Test
    void deleteAllByUserId_shouldRemoveAllTokensForUser() {
        refreshTokenRepository.saveAll(List.of(
                createRefreshToken("hash_session1", 20L),
                createRefreshToken("hash_session2", 20L)
        ));

        refreshTokenRepository.deleteAllByUserId(20L);

        assertThat(refreshTokenRepository.findByTokenHash("hash_session1")).isEmpty();
        assertThat(refreshTokenRepository.findByTokenHash("hash_session2")).isEmpty();
    }

    @Test
    void deleteAllByUserId_shouldNotThrow_whenNoTokens() {
        assertThatCode(() -> refreshTokenRepository.deleteAllByUserId(999L))
                .doesNotThrowAnyException();
    }

    @Test
    void createdAt_shouldBePopulatedOnSave() {
        refreshTokenRepository.save(createRefreshToken("hash_audit", 40L));

        RefreshToken found = refreshTokenRepository.findByTokenHash("hash_audit").orElseThrow();

        assertThat(found.getCreatedAt()).isNotNull();
        assertThat(found.getExpiresAt()).isAfter(LocalDateTime.now());
    }
}

package com.innowise.authservice.repository;

import com.innowise.authservice.TestcontainersConfiguration;
import com.innowise.authservice.config.JpaAuditingConfig;
import com.innowise.authservice.model.Credential;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.context.annotation.Import;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@Import({TestcontainersConfiguration.class, JpaAuditingConfig.class})
class CredentialRepositoryTest {

    @Autowired
    private CredentialRepository credentialRepository;

    private Credential createCredential(Long userId, String email) {
        Credential c = new Credential();
        c.setUserId(userId);
        c.setEmail(email);
        c.setPasswordHash("hashed_password");
        return c;
    }

    @Test
    void findByEmail_shouldReturnSavedCredential() {
        credentialRepository.save(createCredential(1L, "test@example.com"));

        Credential found = credentialRepository.findByEmail("test@example.com").orElseThrow();

        assertThat(found.getEmail()).isEqualTo("test@example.com");
    }

    @Test
    void findByEmail_shouldReturnEmpty_whenNotFound() {
        assertThat(credentialRepository.findByEmail("missing@example.com")).isEmpty();
    }

    @Test
    void findByUserId_shouldReturnCredential() {
        credentialRepository.save(createCredential(42L, "user42@example.com"));

        Credential found = credentialRepository.findByUserId(42L).orElseThrow();

        assertThat(found.getUserId()).isEqualTo(42L);
    }

    @Test
    void findByUserId_shouldReturnEmpty_whenNotFound() {
        assertThat(credentialRepository.findByUserId(999L)).isEmpty();
    }

    @Test
    void existsByEmail_shouldReturnTrue() {
        credentialRepository.save(createCredential(2L, "exists@example.com"));

        assertThat(credentialRepository.existsByEmail("exists@example.com")).isTrue();
    }

    @Test
    void existsByEmail_shouldReturnFalse_whenNotFound() {
        assertThat(credentialRepository.existsByEmail("missing@example.com")).isFalse();
    }

    @Test
    void auditingFields_shouldBePopulatedOnSave() {
        credentialRepository.save(createCredential(3L, "audit@example.com"));

        Credential found = credentialRepository.findByEmail("audit@example.com").orElseThrow();

        assertThat(found.getCreatedAt()).isNotNull();
        assertThat(found.getUpdatedAt()).isNotNull();
    }
}

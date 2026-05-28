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

    @Test
    void findByEmail_shouldReturnSavedCredential() {
        Credential credential = new Credential();
        credential.setUserId(1L);
        credential.setEmail("test@example.com");
        credential.setPasswordHash("hashed_password");
        credentialRepository.save(credential);

        Credential found = credentialRepository.findByEmail("test@example.com").orElseThrow();

        assertThat(found.getEmail()).isEqualTo("test@example.com");
    }

    @Test
    void findByUserId_shouldReturnCredential() {
        Credential credential = new Credential();
        credential.setUserId(42L);
        credential.setEmail("user42@example.com");
        credential.setPasswordHash("hashed_password");
        credentialRepository.save(credential);

        Credential found = credentialRepository.findByUserId(42L).orElseThrow();

        assertThat(found.getUserId()).isEqualTo(42L);
    }

    @Test
    void existsByEmail_shouldReturnTrue() {
        Credential credential = new Credential();
        credential.setUserId(2L);
        credential.setEmail("exists@example.com");
        credential.setPasswordHash("hashed_password");
        credentialRepository.save(credential);

        boolean exists = credentialRepository.existsByEmail("exists@example.com");

        assertThat(exists).isTrue();
    }

    @Test
    void createdAt_shouldBePopulatedOnSave() {
        Credential credential = new Credential();
        credential.setUserId(3L);
        credential.setEmail("audit@example.com");
        credential.setPasswordHash("hashed_password");
        credentialRepository.save(credential);

        Credential found = credentialRepository.findByEmail("audit@example.com").orElseThrow();

        assertThat(found.getCreatedAt()).isNotNull();
    }
}

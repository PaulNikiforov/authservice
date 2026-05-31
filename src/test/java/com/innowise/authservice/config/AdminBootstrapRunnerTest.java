package com.innowise.authservice.config;

import com.innowise.authservice.model.Credential;
import com.innowise.authservice.repository.CredentialRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.boot.ApplicationArguments;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class AdminBootstrapRunnerTest {

    private CredentialRepository credentialRepository;
    private PasswordEncoder passwordEncoder;

    @BeforeEach
    void setUp() {
        credentialRepository = mock(CredentialRepository.class);
        passwordEncoder = mock(PasswordEncoder.class);
    }

    private AdminBootstrapRunner runner(String email, String password, String userId) {
        return new AdminBootstrapRunner(credentialRepository, passwordEncoder,
                new AdminProperties(email, password, userId));
    }

    private static ApplicationArguments args() {
        return mock(ApplicationArguments.class);
    }

    @Test
    void run_whenNoEnvVarsSet_shouldDisableBootstrap() {
        runner("", "", "").run(args());

        verifyNoInteractions(credentialRepository, passwordEncoder);
    }

    @Test
    void run_whenConfigPartial_shouldFailFast() {
        AdminBootstrapRunner runner = runner("admin@test.com", "secret", "");
        ApplicationArguments args = args();

        assertThatThrownBy(() -> runner.run(args))
                .isInstanceOf(IllegalStateException.class);
        verifyNoInteractions(credentialRepository, passwordEncoder);
    }

    @Test
    void run_whenUserIdNonNumeric_shouldFailFast() {
        AdminBootstrapRunner runner = runner("admin@test.com", "secret", "not-a-number");
        ApplicationArguments args = args();

        assertThatThrownBy(() -> runner.run(args))
                .isInstanceOf(IllegalStateException.class);
        verifyNoInteractions(credentialRepository, passwordEncoder);
    }

    @Test
    void run_whenUserIdNonPositive_shouldFailFast() {
        AdminBootstrapRunner runner = runner("admin@test.com", "secret", "0");
        ApplicationArguments args = args();

        assertThatThrownBy(() -> runner.run(args))
                .isInstanceOf(IllegalStateException.class);
        verifyNoInteractions(credentialRepository, passwordEncoder);
    }

    @Test
    void run_whenAdminAlreadyExists_shouldNotCreateCredential() {
        when(credentialRepository.existsByEmail("admin@test.com")).thenReturn(true);

        runner("admin@test.com", "secret", "1").run(args());

        verify(credentialRepository).existsByEmail("admin@test.com");
        verify(credentialRepository, never()).save(any());
        verifyNoInteractions(passwordEncoder);
    }

    @Test
    void run_whenUserIdAlreadyExists_shouldFailFast() {
        when(credentialRepository.existsByEmail("admin@test.com")).thenReturn(false);
        when(credentialRepository.existsByUserId(1L)).thenReturn(true);

        AdminBootstrapRunner runner = runner("admin@test.com", "secret", "1");

        assertThatThrownBy(() -> runner.run(args()))
                .isInstanceOf(IllegalStateException.class);
        verify(credentialRepository, never()).save(any());
        verifyNoInteractions(passwordEncoder);
    }

    @Test
    void run_whenEnvVarsSetAndAdminNotExists_shouldCreateCredentialWithCorrectFields() {
        when(credentialRepository.existsByEmail("admin@test.com")).thenReturn(false);
        when(credentialRepository.existsByUserId(1L)).thenReturn(false);
        when(passwordEncoder.encode("secret")).thenReturn("encoded-secret");

        runner("admin@test.com", "secret", "1").run(args());

        ArgumentCaptor<Credential> captor = ArgumentCaptor.forClass(Credential.class);
        verify(credentialRepository).save(captor.capture());

        Credential saved = captor.getValue();
        assertThat(saved.getUserId()).isEqualTo(1L);
        assertThat(saved.getEmail()).isEqualTo("admin@test.com");
        assertThat(saved.getPasswordHash()).isEqualTo("encoded-secret");
        assertThat(saved.getRole()).isEqualTo("ADMIN");
        assertThat(saved.getIsActive()).isTrue();
    }

    @Test
    void run_whenConcurrentInsertRace_shouldNotPropagate() {
        when(credentialRepository.existsByEmail("admin@test.com")).thenReturn(false);
        when(credentialRepository.existsByUserId(1L)).thenReturn(false);
        when(passwordEncoder.encode("secret")).thenReturn("encoded-secret");
        when(credentialRepository.save(any()))
                .thenThrow(new DataIntegrityViolationException("duplicate key"));
        when(credentialRepository.findByEmail("admin@test.com"))
                .thenReturn(Optional.of(new Credential()));

        AdminBootstrapRunner runner = runner("admin@test.com", "secret", "1");

        assertThatCode(() -> runner.run(args())).doesNotThrowAnyException();
    }

    @Test
    void run_whenIntegrityErrorDidNotCreateAdmin_shouldPropagate() {
        when(credentialRepository.existsByEmail("admin@test.com")).thenReturn(false);
        when(credentialRepository.existsByUserId(1L)).thenReturn(false);
        when(passwordEncoder.encode("secret")).thenReturn("encoded-secret");
        when(credentialRepository.save(any()))
                .thenThrow(new DataIntegrityViolationException("duplicate key"));
        when(credentialRepository.findByEmail("admin@test.com")).thenReturn(Optional.empty());

        AdminBootstrapRunner runner = runner("admin@test.com", "secret", "1");

        assertThatThrownBy(() -> runner.run(args()))
                .isInstanceOf(DataIntegrityViolationException.class);
    }
}

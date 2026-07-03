package com.innowise.authservice.service.impl;

import com.innowise.authservice.exception.InvalidCredentialsException;
import com.innowise.authservice.exception.InvalidTokenException;
import com.innowise.authservice.exception.TokenExpiredException;
import com.innowise.authservice.exception.UserAlreadyExistsException;
import com.innowise.authservice.exception.UserDeactivatedException;
import com.innowise.authservice.model.Credential;
import com.innowise.authservice.model.RefreshToken;
import com.innowise.authservice.repository.CredentialRepository;
import com.innowise.authservice.config.JwtProperties;
import com.innowise.authservice.repository.RefreshTokenRepository;
import com.innowise.authservice.service.JwtService;
import com.innowise.authservice.model.dto.LoginRequest;
import com.innowise.authservice.model.dto.LoginResponse;
import com.innowise.authservice.model.dto.RefreshRequest;
import com.innowise.authservice.model.dto.SaveCredentialsRequest;
import com.innowise.authservice.model.dto.TokenResponse;
import com.innowise.authservice.model.dto.ValidateRequest;
import com.innowise.authservice.model.dto.ValidationResponse;
import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class AuthServiceImplTest {

    private CredentialRepository credentialRepository;
    private RefreshTokenRepository refreshTokenRepository;
    private JwtService jwtService;
    private PasswordEncoder passwordEncoder;
    private AuthServiceImpl authService;

    @BeforeEach
    void setUp() {
        credentialRepository = mock(CredentialRepository.class);
        refreshTokenRepository = mock(RefreshTokenRepository.class);
        jwtService = mock(JwtService.class);
        passwordEncoder = mock(PasswordEncoder.class);

        authService = new AuthServiceImpl(
                credentialRepository, refreshTokenRepository,
                jwtService, passwordEncoder, new JwtProperties("test-private-key", "test-public-key", "test-key-id", 0L, 604_800_000L)
        );

        when(jwtService.generateAccessToken(any(), any())).thenReturn("access.token");
        when(credentialRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(refreshTokenRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
    }

    @Test
    void saveCredentials_shouldEncodePasswordAndReturnTokens() {
        SaveCredentialsRequest request = new SaveCredentialsRequest(1L, "user@test.com", "password123");
        when(credentialRepository.existsByEmail("user@test.com")).thenReturn(false);
        when(passwordEncoder.encode("password123")).thenReturn("$2a$10$hashed");

        TokenResponse response = authService.saveCredentials(request);

        assertThat(response.accessToken()).isEqualTo("access.token");
        assertThat(response.refreshToken()).isNotBlank();
        verify(credentialRepository).save(any(Credential.class));
    }

    @Test
    void saveCredentials_shouldThrow_whenEmailExists() {
        SaveCredentialsRequest request = new SaveCredentialsRequest(1L, "exists@test.com", "password123");
        when(credentialRepository.existsByEmail("exists@test.com")).thenReturn(true);

        assertThatThrownBy(() -> authService.saveCredentials(request))
                .isInstanceOf(UserAlreadyExistsException.class);
    }

    @Test
    void saveCredentials_shouldThrow_whenUserIdExists() {
        SaveCredentialsRequest request = new SaveCredentialsRequest(1L, "new@test.com", "password123");
        when(credentialRepository.existsByEmail("new@test.com")).thenReturn(false);
        when(credentialRepository.existsByUserId(1L)).thenReturn(true);

        assertThatThrownBy(() -> authService.saveCredentials(request))
                .isInstanceOf(UserAlreadyExistsException.class);
    }

    @Test
    void login_shouldReturnTokensAndUserInfo() {
        Credential credential = new Credential();
        credential.setUserId(42L);
        credential.setEmail("user@test.com");
        credential.setPasswordHash("$2a$10$hashed");
        credential.setRole("USER");
        credential.setIsActive(true);

        when(credentialRepository.findByEmail("user@test.com")).thenReturn(Optional.of(credential));
        when(passwordEncoder.matches("password123", "$2a$10$hashed")).thenReturn(true);

        LoginResponse response = authService.login(new LoginRequest("user@test.com", "password123"));

        assertThat(response.userId()).isEqualTo(42L);
        assertThat(response.role()).isEqualTo("USER");
        assertThat(response.accessToken()).isEqualTo("access.token");
        assertThat(response.refreshToken()).isNotBlank();
    }

    @Test
    void login_shouldThrow_whenPasswordMismatch() {
        Credential credential = new Credential();
        credential.setIsActive(true);
        credential.setPasswordHash("$2a$10$hashed");

        when(credentialRepository.findByEmail("user@test.com")).thenReturn(Optional.of(credential));
        when(passwordEncoder.matches("wrong", "$2a$10$hashed")).thenReturn(false);

        LoginRequest request = new LoginRequest("user@test.com", "wrong");
        assertThatThrownBy(() -> authService.login(request))
                .isInstanceOf(InvalidCredentialsException.class);
    }

    @Test
    void login_shouldThrow_whenEmailNotFound() {
        when(credentialRepository.findByEmail("nobody@test.com")).thenReturn(Optional.empty());

        LoginRequest request = new LoginRequest("nobody@test.com", "password123");
        assertThatThrownBy(() -> authService.login(request))
                .isInstanceOf(InvalidCredentialsException.class);
    }

    @Test
    void login_shouldThrow_whenUserDeactivated() {
        Credential credential = new Credential();
        credential.setIsActive(false);
        credential.setPasswordHash("$2a$10$hashed");

        when(credentialRepository.findByEmail("user@test.com")).thenReturn(Optional.of(credential));
        when(passwordEncoder.matches("password123", "$2a$10$hashed")).thenReturn(true);

        LoginRequest request = new LoginRequest("user@test.com", "password123");
        assertThatThrownBy(() -> authService.login(request))
                .isInstanceOf(UserDeactivatedException.class);
    }

    @Test
    void refresh_shouldRotateTokenAndReturnNewPair() {
        RefreshToken existingToken = new RefreshToken();
        existingToken.setTokenHash("abc123");
        existingToken.setUserId(42L);
        existingToken.setExpiresAt(LocalDateTime.now().plusDays(7));

        Credential credential = new Credential();
        credential.setUserId(42L);
        credential.setIsActive(true);
        credential.setRole("USER");

        when(refreshTokenRepository.findByTokenHash(any())).thenReturn(Optional.of(existingToken));
        when(credentialRepository.findByUserId(42L)).thenReturn(Optional.of(credential));

        TokenResponse response = authService.refresh(new RefreshRequest("some-refresh-token"));

        assertThat(response.accessToken()).isEqualTo("access.token");
        assertThat(response.refreshToken()).isNotBlank();
        verify(refreshTokenRepository).delete(existingToken);
        verify(refreshTokenRepository).save(any(RefreshToken.class));
    }

    @Test
    void refresh_shouldThrow_whenTokenNotFound() {
        when(refreshTokenRepository.findByTokenHash(any())).thenReturn(Optional.empty());

        RefreshRequest request = new RefreshRequest("bad-token");
        assertThatThrownBy(() -> authService.refresh(request))
                .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void refresh_shouldThrow_whenTokenExpired() {
        RefreshToken expiredToken = new RefreshToken();
        expiredToken.setTokenHash("abc123");
        expiredToken.setUserId(42L);
        expiredToken.setExpiresAt(LocalDateTime.now().minusDays(1));

        when(refreshTokenRepository.findByTokenHash(any())).thenReturn(Optional.of(expiredToken));

        RefreshRequest request = new RefreshRequest("expired-token");
        assertThatThrownBy(() -> authService.refresh(request))
                .isInstanceOf(TokenExpiredException.class);
    }

    @Test
    void refresh_shouldThrow_whenUserDeactivated() {
        RefreshToken existingToken = new RefreshToken();
        existingToken.setTokenHash("abc123");
        existingToken.setUserId(42L);
        existingToken.setExpiresAt(LocalDateTime.now().plusDays(7));

        Credential credential = new Credential();
        credential.setUserId(42L);
        credential.setIsActive(false);

        when(refreshTokenRepository.findByTokenHash(any())).thenReturn(Optional.of(existingToken));
        when(credentialRepository.findByUserId(42L)).thenReturn(Optional.of(credential));

        RefreshRequest request = new RefreshRequest("some-token");
        assertThatThrownBy(() -> authService.refresh(request))
                .isInstanceOf(UserDeactivatedException.class);
    }

    @Test
    void refresh_shouldThrow_whenCredentialNotFound() {
        RefreshToken existingToken = new RefreshToken();
        existingToken.setTokenHash("abc123");
        existingToken.setUserId(42L);
        existingToken.setExpiresAt(LocalDateTime.now().plusDays(7));

        when(refreshTokenRepository.findByTokenHash(any())).thenReturn(Optional.of(existingToken));
        when(credentialRepository.findByUserId(42L)).thenReturn(Optional.empty());

        RefreshRequest request = new RefreshRequest("some-token");
        assertThatThrownBy(() -> authService.refresh(request))
                .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void logout_shouldDeleteAllRefreshTokensForUser() {
        when(jwtService.extractUserIdLenient("access.token")).thenReturn(42L);

        authService.logout("access.token");

        verify(refreshTokenRepository).deleteAllByUserId(42L);
    }

    @Test
    void logout_shouldWork_withExpiredToken() {
        when(jwtService.extractUserIdLenient("expired.token")).thenReturn(42L);

        authService.logout("expired.token");

        verify(refreshTokenRepository).deleteAllByUserId(42L);
    }

    @Test
    void logout_shouldThrow_whenTokenInvalid() {
        when(jwtService.extractUserIdLenient("garbage"))
                .thenThrow(new InvalidTokenException("Invalid token: malformed"));

        assertThatThrownBy(() -> authService.logout("garbage"))
                .isInstanceOf(InvalidTokenException.class);

        verifyNoInteractions(refreshTokenRepository);
    }

    @Test
    void validate_shouldReturnUserIdAndRole() {
        Claims claims = mock(Claims.class);
        when(claims.get("role", String.class)).thenReturn("ADMIN");
        when(jwtService.validateTokenOrThrow("valid.token")).thenReturn(claims);
        when(jwtService.extractUserId(claims)).thenReturn(42L);

        ValidationResponse response = authService.validate(new ValidateRequest("valid.token"));

        assertThat(response.userId()).isEqualTo(42L);
        assertThat(response.role()).isEqualTo("ADMIN");
    }

    @Test
    void validate_shouldThrow_whenRoleMissing() {
        Claims claims = mock(Claims.class);
        when(claims.get("role", String.class)).thenReturn(null);
        when(jwtService.validateTokenOrThrow("missing-role.token")).thenReturn(claims);
        when(jwtService.extractUserId(claims)).thenReturn(42L);

        ValidateRequest request = new ValidateRequest("missing-role.token");
        assertThatThrownBy(() -> authService.validate(request))
                .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void validate_shouldThrow_whenRoleBlank() {
        Claims claims = mock(Claims.class);
        when(claims.get("role", String.class)).thenReturn(" ");
        when(jwtService.validateTokenOrThrow("blank-role.token")).thenReturn(claims);
        when(jwtService.extractUserId(claims)).thenReturn(42L);

        ValidateRequest request = new ValidateRequest("blank-role.token");
        assertThatThrownBy(() -> authService.validate(request))
                .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void validate_shouldThrow_whenTokenInvalid() {
        when(jwtService.validateTokenOrThrow("bad.token"))
                .thenThrow(new InvalidTokenException("Invalid token: bad signature"));

        ValidateRequest request = new ValidateRequest("bad.token");
        assertThatThrownBy(() -> authService.validate(request))
                .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void validate_shouldThrow_whenTokenExpired() {
        when(jwtService.validateTokenOrThrow("expired.token"))
                .thenThrow(new TokenExpiredException("Token has expired"));

        ValidateRequest request = new ValidateRequest("expired.token");
        assertThatThrownBy(() -> authService.validate(request))
                .isInstanceOf(TokenExpiredException.class);
    }
}

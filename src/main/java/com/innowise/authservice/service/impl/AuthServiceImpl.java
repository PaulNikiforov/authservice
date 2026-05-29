package com.innowise.authservice.service.impl;

import com.innowise.authservice.exception.InvalidCredentialsException;
import com.innowise.authservice.exception.InvalidTokenException;
import com.innowise.authservice.exception.TokenExpiredException;
import com.innowise.authservice.exception.UserAlreadyExistsException;
import com.innowise.authservice.exception.UserDeactivatedException;
import com.innowise.authservice.model.Credential;
import com.innowise.authservice.model.RefreshToken;
import com.innowise.authservice.repository.CredentialRepository;
import com.innowise.authservice.repository.RefreshTokenRepository;
import com.innowise.authservice.service.AuthService;
import com.innowise.authservice.service.JwtService;
import com.innowise.authservice.service.dto.LoginRequest;
import com.innowise.authservice.service.dto.LoginResponse;
import com.innowise.authservice.service.dto.RefreshRequest;
import com.innowise.authservice.service.dto.SaveCredentialsRequest;
import com.innowise.authservice.service.dto.TokenResponse;
import com.innowise.authservice.service.dto.ValidateRequest;
import com.innowise.authservice.service.dto.ValidationResponse;
import com.innowise.authservice.util.TokenHasher;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

@Service
public class AuthServiceImpl implements AuthService {

    private final CredentialRepository credentialRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final long refreshExpiration;

    public AuthServiceImpl(CredentialRepository credentialRepository,
                           RefreshTokenRepository refreshTokenRepository,
                           JwtService jwtService,
                           PasswordEncoder passwordEncoder,
                           @Value("${jwt.refresh-expiration}") long refreshExpiration) {
        this.credentialRepository = credentialRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.jwtService = jwtService;
        this.passwordEncoder = passwordEncoder;
        this.refreshExpiration = refreshExpiration;
    }

    @Override
    @Transactional
    public TokenResponse saveCredentials(SaveCredentialsRequest request) {
        if (credentialRepository.existsByEmail(request.email())) {
            throw new UserAlreadyExistsException("Email already registered");
        }
        if (credentialRepository.existsByUserId(request.userId())) {
            throw new UserAlreadyExistsException("User already has credentials");
        }

        Credential credential = Credential.of(request.userId(), request.email(),
                passwordEncoder.encode(request.password()), Credential.DEFAULT_ROLE);
        credentialRepository.save(credential);

        return generateTokenPair(credential.getUserId(), credential.getRole());
    }

    @Override
    @Transactional
    public LoginResponse login(LoginRequest request) {
        Credential credential = credentialRepository.findByEmail(request.email())
                .orElseThrow(() -> new InvalidCredentialsException("Invalid email or password"));

        if (!passwordEncoder.matches(request.password(), credential.getPasswordHash())) {
            throw new InvalidCredentialsException("Invalid email or password");
        }

        if (!credential.getIsActive()) {
            throw new UserDeactivatedException("Account is deactivated");
        }

        TokenResponse tokens = generateTokenPair(credential.getUserId(), credential.getRole());
        return new LoginResponse(tokens.accessToken(), tokens.refreshToken(),
                credential.getUserId(), credential.getRole());
    }

    @Override
    @Transactional
    public TokenResponse refresh(RefreshRequest request) {
        String tokenHash = TokenHasher.sha256Hex(request.refreshToken());

        RefreshToken existing = refreshTokenRepository.findByTokenHash(tokenHash)
                .orElseThrow(() -> new InvalidTokenException("Invalid refresh token"));

        if (existing.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw new TokenExpiredException("Refresh token has expired");
        }

        Credential credential = credentialRepository.findByUserId(existing.getUserId())
                .orElseThrow(() -> new InvalidTokenException("No credentials found for token owner"));

        if (!credential.getIsActive()) {
            throw new UserDeactivatedException("Account is deactivated");
        }

        refreshTokenRepository.delete(existing);

        return generateTokenPair(credential.getUserId(), credential.getRole());
    }

    @Override
    @Transactional
    public void logout(String accessToken) {
        Long userId = jwtService.extractUserIdLenient(accessToken);
        refreshTokenRepository.deleteAllByUserId(userId);
    }

    @Override
    @Transactional(readOnly = true)
    public ValidationResponse validate(ValidateRequest request) {
        var claims = jwtService.validateTokenOrThrow(request.accessToken());
        Long userId = jwtService.extractUserId(claims);
        String role = claims.get("role", String.class);
        return new ValidationResponse(userId, role);
    }

    private TokenResponse generateTokenPair(Long userId, String role) {
        String accessToken = jwtService.generateAccessToken(userId, role);
        String refreshToken = saveRefreshToken(userId);
        return new TokenResponse(accessToken, refreshToken);
    }

    private String saveRefreshToken(Long userId) {
        String rawToken = UUID.randomUUID().toString();
        String tokenHash = TokenHasher.sha256Hex(rawToken);

        refreshTokenRepository.save(RefreshToken.of(tokenHash, userId, calculateRefreshExpiresAt()));

        return rawToken;
    }

    private LocalDateTime calculateRefreshExpiresAt() {
        // Same clock/zone as JPA auditing (createdAt) and the expiry check in refresh()
        return LocalDateTime.now().plus(refreshExpiration, ChronoUnit.MILLIS);
    }
}

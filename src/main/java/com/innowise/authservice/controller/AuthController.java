package com.innowise.authservice.controller;

import com.innowise.authservice.exception.InvalidTokenException;
import com.innowise.authservice.service.AuthService;
import com.innowise.authservice.model.dto.LoginRequest;
import com.innowise.authservice.model.dto.LoginResponse;
import com.innowise.authservice.model.dto.RefreshRequest;
import com.innowise.authservice.model.dto.SaveCredentialsRequest;
import com.innowise.authservice.model.dto.TokenResponse;
import com.innowise.authservice.model.dto.ValidateRequest;
import com.innowise.authservice.model.dto.ValidationResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Tag(name = "Auth", description = "Authentication and token management")
public class AuthController {

    private static final String BEARER_PREFIX = "Bearer ";

    private final AuthService authService;

    @PostMapping("/credentials")
    @Operation(summary = "Register new user credentials")
    public ResponseEntity<TokenResponse> saveCredentials(@Valid @RequestBody SaveCredentialsRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.saveCredentials(request));
    }

    @PostMapping("/login")
    @Operation(summary = "Authenticate user and get tokens")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    @PostMapping("/refresh")
    @Operation(summary = "Refresh access token pair")
    public ResponseEntity<TokenResponse> refresh(@Valid @RequestBody RefreshRequest request) {
        return ResponseEntity.ok(authService.refresh(request));
    }

    @PostMapping("/logout")
    @Operation(summary = "Revoke all refresh tokens for user", security = @SecurityRequirement(name = "bearerAuth"))
    public ResponseEntity<Void> logout(
            @Parameter(hidden = true)
            @RequestHeader(name = "Authorization", required = false) String authorization) {
        if (authorization == null || !authorization.startsWith(BEARER_PREFIX)) {
            throw new InvalidTokenException("Missing or malformed Authorization header");
        }
        String token = authorization.substring(BEARER_PREFIX.length());
        if (token.isBlank()) {
            throw new InvalidTokenException("Authorization token must not be empty");
        }
        authService.logout(token);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/validate")
    @Operation(summary = "Validate access token and extract claims")
    public ResponseEntity<ValidationResponse> validate(@Valid @RequestBody ValidateRequest request) {
        return ResponseEntity.ok(authService.validate(request));
    }
}

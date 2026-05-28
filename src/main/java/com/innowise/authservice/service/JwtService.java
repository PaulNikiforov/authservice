package com.innowise.authservice.service;

import com.innowise.authservice.exception.InvalidTokenException;
import com.innowise.authservice.exception.TokenExpiredException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

@Service
public class JwtService {

    private final SecretKey signingKey;
    private final long accessExpiration;
    private final long refreshExpiration;

    public JwtService(@Value("${jwt.secret}") String secret,
                      @Value("${jwt.access-expiration}") long accessExpiration,
                      @Value("${jwt.refresh-expiration}") long refreshExpiration) {
        this.signingKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.accessExpiration = accessExpiration;
        this.refreshExpiration = refreshExpiration;
    }

    public String generateAccessToken(Long userId, String role) {
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(userId.toString())
                .claim("role", role)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusMillis(accessExpiration)))
                .signWith(signingKey)
                .compact();
    }

    public LocalDateTime calculateRefreshExpiresAt() {
        return LocalDateTime.ofInstant(Instant.now().plusMillis(refreshExpiration), ZoneId.of("UTC"));
    }

    public Claims validateTokenOrThrow(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(signingKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (ExpiredJwtException e) {
            throw new TokenExpiredException("Token has expired");
        } catch (JwtException e) {
            throw new InvalidTokenException("Invalid token: " + e.getMessage());
        }
    }

    public Long extractUserId(String token) {
        return Long.parseLong(validateTokenOrThrow(token).getSubject());
    }

    public String extractRole(String token) {
        return validateTokenOrThrow(token).get("role", String.class);
    }
}

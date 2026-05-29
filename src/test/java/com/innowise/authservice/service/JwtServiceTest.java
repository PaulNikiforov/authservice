package com.innowise.authservice.service;

import com.innowise.authservice.config.JwtProperties;
import com.innowise.authservice.exception.InvalidTokenException;
import com.innowise.authservice.exception.TokenException;
import com.innowise.authservice.exception.TokenExpiredException;
import com.innowise.authservice.service.impl.JwtServiceImpl;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtServiceTest {

    private static final String SECRET = "testsecretkey1234567890abcdefghij";
    private static final long ACCESS_EXPIRATION = 900_000L;

    private JwtService jwtService;

    @BeforeEach
    void setUp() {
        jwtService = new JwtServiceImpl(new JwtProperties(SECRET, ACCESS_EXPIRATION, 0L));
    }

    @Test
    void generateAccessToken_shouldContainUserIdAndRole() {
        String token = jwtService.generateAccessToken(42L, "ADMIN");

        SecretKey key = Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));
        Claims claims = Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        assertThat(claims.getSubject()).isEqualTo("42");
        assertThat(claims.get("role", String.class)).isEqualTo("ADMIN");
        assertThat(claims.getExpiration()).isNotNull();
    }

    @Test
    void validateTokenOrThrow_withExpiredToken_throwsTokenExpiredException() {
        SecretKey key = Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));
        String expiredToken = Jwts.builder()
                .subject("1")
                .claim("role", "USER")
                .issuedAt(new Date(System.currentTimeMillis() - 10_000))
                .expiration(new Date(System.currentTimeMillis() - 5_000))
                .signWith(key)
                .compact();

        assertThatThrownBy(() -> jwtService.validateTokenOrThrow(expiredToken))
                .isInstanceOf(TokenExpiredException.class);
    }

    @Test
    void validateTokenOrThrow_withTamperedToken_throwsInvalidTokenException() {
        String validToken = jwtService.generateAccessToken(1L, "USER");
        String tampered = validToken.substring(0, validToken.lastIndexOf('.') + 1) + "invalidsignature";

        assertThatThrownBy(() -> jwtService.validateTokenOrThrow(tampered))
                .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void tokenExceptions_shouldFollowSealedHierarchy() {
        assertThat(TokenException.class).isSealed();
        assertThat(TokenExpiredException.class).isAssignableTo(TokenException.class);
        assertThat(InvalidTokenException.class).isAssignableTo(TokenException.class);
    }

    @Test
    void extractUserId_fromClaims_returnsCorrectId() {
        Claims claims = jwtService.validateTokenOrThrow(jwtService.generateAccessToken(99L, "USER"));
        assertThat(jwtService.extractUserId(claims)).isEqualTo(99L);
    }

    @Test
    void extractUserId_fromClaimsWithNonNumericSubject_throwsInvalidToken() {
        SecretKey key = Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));
        Claims claims = Jwts.parser().verifyWith(key).build()
                .parseSignedClaims(Jwts.builder().subject("not-a-number").signWith(key).compact())
                .getPayload();

        assertThatThrownBy(() -> jwtService.extractUserId(claims))
                .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void extractUserIdLenient_withValidToken_returnsUserId() {
        String token = jwtService.generateAccessToken(42L, "USER");
        assertThat(jwtService.extractUserIdLenient(token)).isEqualTo(42L);
    }

    @Test
    void extractUserIdLenient_withExpiredToken_returnsUserId() {
        SecretKey key = Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));
        String expiredToken = Jwts.builder()
                .subject("77")
                .claim("role", "USER")
                .issuedAt(new Date(System.currentTimeMillis() - 10_000))
                .expiration(new Date(System.currentTimeMillis() - 5_000))
                .signWith(key)
                .compact();

        assertThat(jwtService.extractUserIdLenient(expiredToken)).isEqualTo(77L);
    }

    @Test
    void extractUserIdLenient_withInvalidToken_throwsInvalidTokenException() {
        assertThatThrownBy(() -> jwtService.extractUserIdLenient("garbage.token.here"))
                .isInstanceOf(InvalidTokenException.class);
    }
}

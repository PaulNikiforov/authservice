package com.innowise.authservice.service;

import com.innowise.authservice.config.JwtProperties;
import com.innowise.authservice.exception.InvalidTokenException;
import com.innowise.authservice.exception.TokenExpiredException;
import com.innowise.authservice.service.impl.JwtServiceImpl;
import com.innowise.authservice.support.RsaTestKeys;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Jwk;
import io.jsonwebtoken.security.JwkSet;
import io.jsonwebtoken.security.RsaPublicJwk;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtServiceTest {

    private static final String KEY_ID = "test-key-1";
    private static final long ACCESS_EXPIRATION = 900_000L;

    private static KeyPair keyPair;
    private static String privateKeyPem;
    private static String publicKeyPem;

    private JwtService jwtService;

    @BeforeAll
    static void generateKeyPair() {
        RsaTestKeys.Pair keys = RsaTestKeys.generate();
        keyPair = keys.keyPair();
        privateKeyPem = keys.privateKeyPem();
        publicKeyPem = keys.publicKeyPem();
    }

    @BeforeEach
    void setUp() {
        jwtService = new JwtServiceImpl(new JwtProperties(privateKeyPem, publicKeyPem, KEY_ID, ACCESS_EXPIRATION, 0L));
    }

    @Test
    void generateAccessToken_shouldContainUserIdAndRole() {
        String token = jwtService.generateAccessToken(42L, "ADMIN");

        Jws<Claims> jws = Jwts.parser()
                .verifyWith(keyPair.getPublic())
                .build()
                .parseSignedClaims(token);

        JwsHeader header = jws.getHeader();
        Claims claims = jws.getPayload();

        assertThat(header.getAlgorithm()).isEqualTo("RS256");
        assertThat(header.getKeyId()).isEqualTo(KEY_ID);
        assertThat(claims.getSubject()).isEqualTo("42");
        assertThat(claims.get("role", String.class)).isEqualTo("ADMIN");
        assertThat(claims.getExpiration()).isNotNull();
    }

    @Test
    void validateTokenOrThrow_withExpiredToken_throwsTokenExpiredException() {
        String expiredToken = Jwts.builder()
                .header().keyId(KEY_ID).and()
                .subject("1")
                .claim("role", "USER")
                .issuedAt(new Date(System.currentTimeMillis() - 10_000))
                .expiration(new Date(System.currentTimeMillis() - 5_000))
                .signWith(keyPair.getPrivate(), Jwts.SIG.RS256)
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
    void extractUserId_fromClaims_returnsCorrectId() {
        Claims claims = jwtService.validateTokenOrThrow(jwtService.generateAccessToken(99L, "USER"));
        assertThat(jwtService.extractUserId(claims)).isEqualTo(99L);
    }

    @Test
    void extractUserId_fromClaimsWithNonNumericSubject_throwsInvalidToken() {
        Claims claims = Jwts.parser().verifyWith(keyPair.getPublic()).build()
                .parseSignedClaims(Jwts.builder()
                        .subject("not-a-number")
                        .signWith(keyPair.getPrivate(), Jwts.SIG.RS256)
                        .compact())
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
        String expiredToken = Jwts.builder()
                .header().keyId(KEY_ID).and()
                .subject("77")
                .claim("role", "USER")
                .issuedAt(new Date(System.currentTimeMillis() - 10_000))
                .expiration(new Date(System.currentTimeMillis() - 5_000))
                .signWith(keyPair.getPrivate(), Jwts.SIG.RS256)
                .compact();

        assertThat(jwtService.extractUserIdLenient(expiredToken)).isEqualTo(77L);
    }

    @Test
    void extractUserIdLenient_withInvalidToken_throwsInvalidTokenException() {
        assertThatThrownBy(() -> jwtService.extractUserIdLenient("garbage.token.here"))
                .isInstanceOf(InvalidTokenException.class);
    }

    @Test
    void getJwkSet_returnsSingleRsaPublicKeyWithConfiguredMetadata() {
        JwkSet jwkSet = jwtService.getJwkSet();

        List<Jwk<?>> keys = new ArrayList<>(jwkSet.getKeys());
        assertThat(keys).hasSize(1);

        RsaPublicJwk jwk = (RsaPublicJwk) keys.get(0);
        assertThat(jwk.getType()).isEqualTo("RSA");
        assertThat(jwk.getAlgorithm()).isEqualTo("RS256");
        assertThat(jwk.getPublicKeyUse()).isEqualTo("sig");
        assertThat(jwk.getId()).isEqualTo(KEY_ID);

        RSAPublicKey recoveredKey = jwk.toKey();
        assertThat(recoveredKey).isEqualTo(keyPair.getPublic());
    }
}

package com.innowise.authservice.service.impl;

import com.innowise.authservice.config.JwtProperties;
import com.innowise.authservice.exception.InvalidTokenException;
import com.innowise.authservice.exception.TokenExpiredException;
import com.innowise.authservice.service.JwtService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Jwks;
import io.jsonwebtoken.security.JwkSet;
import io.jsonwebtoken.security.RsaPublicJwk;
import org.springframework.stereotype.Service;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;

@Service
public class JwtServiceImpl implements JwtService {

    private final PrivateKey privateKey;
    private final PublicKey publicKey;
    private final String keyId;
    private final long accessExpiration;
    private final JwkSet jwkSet;

    public JwtServiceImpl(JwtProperties jwtProperties) {
        this.privateKey = parsePrivateKey(jwtProperties.privateKey());
        this.publicKey = parsePublicKey(jwtProperties.publicKey());
        this.keyId = jwtProperties.keyId();
        this.accessExpiration = jwtProperties.accessExpiration();
        this.jwkSet = buildJwkSet((RSAPublicKey) publicKey, keyId);
    }

    @Override
    public String generateAccessToken(Long userId, String role) {
        Instant now = Instant.now();
        return Jwts.builder()
                .header().keyId(keyId).and()
                .subject(userId.toString())
                .claim("role", role)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusMillis(accessExpiration)))
                .signWith(privateKey, Jwts.SIG.RS256)
                .compact();
    }

    @Override
    public Claims validateTokenOrThrow(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(publicKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (ExpiredJwtException e) {
            throw new TokenExpiredException("Token has expired");
        } catch (JwtException e) {
            throw new InvalidTokenException("Invalid token: " + e.getMessage());
        }
    }

    @Override
    public Long extractUserId(Claims claims) {
        try {
            return Long.parseLong(claims.getSubject());
        } catch (NumberFormatException e) {
            throw new InvalidTokenException("Token subject is not a valid user id");
        }
    }

    @Override
    public Long extractUserIdLenient(String token) {
        Claims claims;
        try {
            claims = Jwts.parser()
                    .verifyWith(publicKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (ExpiredJwtException e) {
            claims = e.getClaims();
        } catch (JwtException e) {
            throw new InvalidTokenException("Invalid token: " + e.getMessage());
        }
        return extractUserId(claims);
    }

    @Override
    public JwkSet getJwkSet() {
        return jwkSet;
    }

    private static JwkSet buildJwkSet(RSAPublicKey publicKey, String keyId) {
        RsaPublicJwk jwk = Jwks.builder()
                .key(publicKey)
                .id(keyId)
                .algorithm(Jwts.SIG.RS256.getId())
                .publicKeyUse("sig")
                .build();
        return Jwks.set().add(jwk).build();
    }

    private static PrivateKey parsePrivateKey(String pem) {
        try {
            byte[] decoded = Base64.getDecoder().decode(clean(pem));
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decoded));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException("Invalid RSA private key configuration", e);
        }
    }

    private static PublicKey parsePublicKey(String pem) {
        try {
            byte[] decoded = Base64.getDecoder().decode(clean(pem));
            return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decoded));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException("Invalid RSA public key configuration", e);
        }
    }

    private static String clean(String pem) {
        return pem
                .replaceAll("-----BEGIN [A-Z ]+-----", "")
                .replaceAll("-----END [A-Z ]+-----", "")
                .replaceAll("\\s", "");
    }
}

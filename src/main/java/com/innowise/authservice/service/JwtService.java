package com.innowise.authservice.service;

import io.jsonwebtoken.Claims;

/**
 * Issues and validates access tokens (JWT, HMAC-SHA256). Implemented by
 * {@code com.innowise.authservice.service.impl.JwtServiceImpl}.
 */
public interface JwtService {

    /**
     * Generates a signed access token with {@code sub = userId} and a {@code role} claim.
     */
    String generateAccessToken(Long userId, String role);

    /**
     * Verifies the signature and expiry of {@code token} and returns its claims.
     *
     * @throws com.innowise.authservice.exception.TokenExpiredException if the token has expired
     * @throws com.innowise.authservice.exception.InvalidTokenException if the token is malformed or its signature is invalid
     */
    Claims validateTokenOrThrow(String token);

    /**
     * Extracts the user id from the {@code sub} claim.
     *
     * @throws com.innowise.authservice.exception.InvalidTokenException if {@code sub} is not a valid Long
     */
    Long extractUserId(Claims claims);

    /**
     * Extracts the user id from a token, tolerating expiry (used on logout, where an expired
     * access token must still identify its owner). A malformed/forged token is still rejected.
     *
     * @throws com.innowise.authservice.exception.InvalidTokenException if the token is malformed or its signature is invalid
     */
    Long extractUserIdLenient(String token);
}

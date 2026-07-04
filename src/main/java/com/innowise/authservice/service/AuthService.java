package com.innowise.authservice.service;

import com.innowise.authservice.model.dto.LoginRequest;
import com.innowise.authservice.model.dto.LoginResponse;
import com.innowise.authservice.model.dto.RefreshRequest;
import com.innowise.authservice.model.dto.SaveCredentialsRequest;
import com.innowise.authservice.model.dto.TokenResponse;

/**
 * Core authentication operations: credential storage, login, token rotation and logout.
 * Implemented by {@code com.innowise.authservice.service.impl.AuthServiceImpl}.
 *
 * <p>Auth Service is not the source of truth for user identity (that is the User Service);
 * it owns only credentials and refresh tokens. Refresh tokens are stored as SHA-256 hashes,
 * and HTTP status mapping for the exceptions below is handled by the global exception handler.
 */
public interface AuthService {

    /**
     * Stores credentials for a user that already exists in the User Service and issues the
     * initial access/refresh token pair.
     *
     * @throws com.innowise.authservice.exception.UserAlreadyExistsException if the email or
     *         user id already has credentials (mapped to {@code 409 Conflict})
     */
    TokenResponse saveCredentials(SaveCredentialsRequest request);

    /**
     * Authenticates by email and password and returns a fresh token pair together with the
     * user's id and role.
     *
     * @throws com.innowise.authservice.exception.InvalidCredentialsException for an unknown
     *         email or a wrong password — the same message is used for both (anti-enumeration),
     *         mapped to {@code 401 Unauthorized}
     * @throws com.innowise.authservice.exception.UserDeactivatedException if the account is
     *         deactivated (mapped to {@code 403 Forbidden})
     */
    LoginResponse login(LoginRequest request);

    /**
     * Rotates a refresh token: validates it, deletes the presented token and issues a new
     * access/refresh pair.
     *
     * @throws com.innowise.authservice.exception.InvalidTokenException if the refresh token is
     *         unknown (mapped to {@code 401 Unauthorized})
     * @throws com.innowise.authservice.exception.TokenExpiredException if the refresh token has
     *         expired (mapped to {@code 401 Unauthorized})
     * @throws com.innowise.authservice.exception.UserDeactivatedException if the token owner is
     *         deactivated (mapped to {@code 403 Forbidden})
     */
    TokenResponse refresh(RefreshRequest request);

    /**
     * Logs the caller out by deleting <strong>all</strong> refresh tokens of the access
     * token's owner (terminates every session). Tolerates an expired access token, since
     * logout must still identify the owner.
     *
     * @param accessToken the bearer access token identifying the user
     */
    void logout(String accessToken);
}

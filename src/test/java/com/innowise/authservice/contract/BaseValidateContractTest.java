package com.innowise.authservice.contract;

import com.innowise.authservice.service.JwtService;
import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Base class for the {@code should_validate_token} contract.
 *
 * <p>Mocks {@link JwtService} so that any non-blank string is accepted as a valid
 * access token. This isolates the contract test from JWT implementation details
 * (key rotation, expiry, algorithm) which are covered by unit and integration tests.
 *
 * <p>The contract verifies what the endpoint RETURNS (userId + role shape), not
 * how JWT parsing works internally.
 */
public abstract class BaseValidateContractTest extends BaseContractTest {

    @MockitoBean
    private JwtService jwtService;

    @BeforeEach
    void stubJwtService() {
        Claims mockClaims = mock(Claims.class);
        when(mockClaims.get("role", String.class)).thenReturn("USER");
        when(jwtService.validateTokenOrThrow(anyString())).thenReturn(mockClaims);
        when(jwtService.extractUserId(any(Claims.class))).thenReturn(CONTRACT_USER_ID);
    }
}

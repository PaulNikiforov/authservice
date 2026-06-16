package com.innowise.authservice.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.innowise.authservice.TestcontainersConfiguration;
import com.innowise.authservice.model.Credential;
import com.innowise.authservice.model.RefreshToken;
import com.innowise.authservice.repository.CredentialRepository;
import com.innowise.authservice.repository.RefreshTokenRepository;
import com.innowise.authservice.service.JwtService;
import com.innowise.authservice.model.dto.LoginRequest;
import com.innowise.authservice.model.dto.LoginResponse;
import com.innowise.authservice.model.dto.RefreshRequest;
import com.innowise.authservice.model.dto.SaveCredentialsRequest;
import com.innowise.authservice.model.dto.TokenResponse;
import com.innowise.authservice.model.dto.ValidateRequest;
import com.innowise.authservice.util.TokenHasher;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Import(TestcontainersConfiguration.class)
class AuthControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private CredentialRepository credentialRepository;
    @Autowired
    private RefreshTokenRepository refreshTokenRepository;
    @Autowired
    private JwtService jwtService;

    @BeforeEach
    void setUp() {
        refreshTokenRepository.deleteAll();
        credentialRepository.deleteAll();
    }

    @Nested
    class FullFlow {

        @Test
        void shouldWorkEndToEnd() throws Exception {
            performSave(100L, "flow@int.test", "password123")
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.accessToken").isNotEmpty())
                    .andExpect(jsonPath("$.refreshToken").isNotEmpty());

            MvcResult loginResult = performLogin("flow@int.test", "password123")
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.userId").value(100))
                    .andExpect(jsonPath("$.role").value("USER"))
                    .andReturn();
            LoginResponse loginResp = body(loginResult, LoginResponse.class);

            MvcResult refreshResult = performRefresh(loginResp.refreshToken())
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.accessToken").isNotEmpty())
                    .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                    .andReturn();
            TokenResponse refreshTokens = body(refreshResult, TokenResponse.class);

            performValidate(refreshTokens.accessToken())
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.userId").value(100))
                    .andExpect(jsonPath("$.role").value("USER"));

            mockMvc.perform(post("/api/v1/auth/logout")
                            .header("Authorization", "Bearer " + refreshTokens.accessToken()))
                    .andExpect(status().isOk());

            performRefresh(refreshTokens.refreshToken())
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.status").value(401))
                    .andExpect(jsonPath("$.error").value("Unauthorized"))
                    .andExpect(jsonPath("$.message").isNotEmpty())
                    .andExpect(jsonPath("$.path").value("/api/v1/auth/refresh"));
        }
    }

    @Nested
    class ErrorCases {

        @Test
        void duplicateEmail_shouldReturn409() throws Exception {
            performSave(200L, "dup@int.test", "password123").andExpect(status().isCreated());

            performSave(201L, "dup@int.test", "otherpass1")
                    .andExpect(status().isConflict())
                    .andExpect(jsonPath("$.status").value(409))
                    .andExpect(jsonPath("$.error").value("Conflict"))
                    .andExpect(jsonPath("$.message").value("Email already registered"))
                    .andExpect(jsonPath("$.path").value("/api/v1/auth/credentials"));
        }

        @Test
        void wrongPassword_shouldReturn401() throws Exception {
            performSave(300L, "wrongpw@int.test", "password123").andExpect(status().isCreated());

            performLogin("wrongpw@int.test", "wrongpassword")
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.status").value(401))
                    .andExpect(jsonPath("$.error").value("Unauthorized"))
                    .andExpect(jsonPath("$.message").value("Invalid email or password"))
                    .andExpect(jsonPath("$.path").value("/api/v1/auth/login"));
        }

        @Test
        void deactivatedUser_shouldReturn403() throws Exception {
            performSave(400L, "deactivated@int.test", "password123").andExpect(status().isCreated());

            Credential credential = credentialRepository.findByEmail("deactivated@int.test").orElseThrow();
            credential.setIsActive(false);
            credentialRepository.save(credential);

            performLogin("deactivated@int.test", "password123")
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.status").value(403))
                    .andExpect(jsonPath("$.error").value("Forbidden"))
                    .andExpect(jsonPath("$.message").value("Account is deactivated"))
                    .andExpect(jsonPath("$.path").value("/api/v1/auth/login"));
        }

        @Test
        void expiredRefreshToken_shouldReturn401() throws Exception {
            MvcResult result = performSave(500L, "expired@int.test", "password123")
                    .andExpect(status().isCreated()).andReturn();
            String refreshToken = body(result, TokenResponse.class).refreshToken();

            String tokenHash = TokenHasher.sha256Hex(refreshToken);
            RefreshToken token = refreshTokenRepository.findByTokenHash(tokenHash).orElseThrow();
            token.setExpiresAt(LocalDateTime.now().minusHours(1));
            refreshTokenRepository.save(token);

            performRefresh(refreshToken)
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.status").value(401))
                    .andExpect(jsonPath("$.error").value("Unauthorized"))
                    .andExpect(jsonPath("$.message").value("Refresh token has expired"))
                    .andExpect(jsonPath("$.path").value("/api/v1/auth/refresh"));
        }

        @Test
        void malformedToken_shouldReturn401() throws Exception {
            performValidate("invalid.jwt.token")
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.status").value(401))
                    .andExpect(jsonPath("$.error").value("Unauthorized"))
                    .andExpect(jsonPath("$.message").isNotEmpty())
                    .andExpect(jsonPath("$.path").value("/api/v1/auth/validate"));
        }

        @Test
        void tokenSignedWithWrongKey_shouldReturn401() throws Exception {
            SecretKey foreignKey = Keys.hmacShaKeyFor(
                    "a-totally-different-secret-key-1234567890".getBytes(StandardCharsets.UTF_8));
            String forgedToken = Jwts.builder()
                    .subject("999")
                    .claim("role", "USER")
                    .signWith(foreignKey)
                    .compact();

            performValidate(forgedToken)
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.status").value(401))
                    .andExpect(jsonPath("$.error").value("Unauthorized"))
                    .andExpect(jsonPath("$.message").isNotEmpty())
                    .andExpect(jsonPath("$.path").value("/api/v1/auth/validate"));
        }
    }

    @Nested
    class JwtClaims {

        @Test
        void shouldContainCorrectUserIdAndRole() throws Exception {
            MvcResult result = performSave(600L, "claims@int.test", "password123")
                    .andExpect(status().isCreated()).andReturn();
            String accessToken = body(result, TokenResponse.class).accessToken();

            Claims claims = jwtService.validateTokenOrThrow(accessToken);

            assertThat(claims.getSubject()).isEqualTo("600");
            assertThat(Long.parseLong(claims.getSubject())).isEqualTo(600L);
            assertThat(claims.get("role", String.class)).isEqualTo("USER");
        }
    }

    private ResultActions performSave(Long userId, String email, String password) throws Exception {
        SaveCredentialsRequest request = new SaveCredentialsRequest(userId, email, password);
        return mockMvc.perform(post("/api/v1/auth/credentials")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)));
    }

    private ResultActions performLogin(String email, String password) throws Exception {
        LoginRequest request = new LoginRequest(email, password);
        return mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)));
    }

    private ResultActions performRefresh(String refreshToken) throws Exception {
        RefreshRequest request = new RefreshRequest(refreshToken);
        return mockMvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)));
    }

    private ResultActions performValidate(String accessToken) throws Exception {
        ValidateRequest request = new ValidateRequest(accessToken);
        return mockMvc.perform(post("/api/v1/auth/validate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)));
    }

    private <T> T body(MvcResult result, Class<T> type) throws Exception {
        return objectMapper.readValue(result.getResponse().getContentAsString(), type);
    }
}

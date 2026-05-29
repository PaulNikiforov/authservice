package com.innowise.authservice.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.innowise.authservice.service.AuthService;
import com.innowise.authservice.model.dto.LoginRequest;
import com.innowise.authservice.model.dto.LoginResponse;
import com.innowise.authservice.model.dto.RefreshRequest;
import com.innowise.authservice.model.dto.SaveCredentialsRequest;
import com.innowise.authservice.model.dto.TokenResponse;
import com.innowise.authservice.model.dto.ValidateRequest;
import com.innowise.authservice.model.dto.ValidationResponse;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AuthController.class)
@AutoConfigureMockMvc(addFilters = false)
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private AuthService authService;

    @Autowired
    private ObjectMapper objectMapper;

    @Nested
    class HappyPath {

        @Test
        void saveCredentials_shouldReturn201WithTokens() throws Exception {
            SaveCredentialsRequest request = new SaveCredentialsRequest(1L, "user@example.com", "password123");
            given(authService.saveCredentials(any(SaveCredentialsRequest.class)))
                    .willReturn(new TokenResponse("access-token", "refresh-token"));

            mockMvc.perform(post("/auth/credentials")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isCreated())
                    .andExpect(jsonPath("$.accessToken").value("access-token"))
                    .andExpect(jsonPath("$.refreshToken").value("refresh-token"));
        }

        @Test
        void login_shouldReturn200WithTokensAndUserInfo() throws Exception {
            LoginRequest request = new LoginRequest("user@example.com", "password123");
            given(authService.login(any(LoginRequest.class)))
                    .willReturn(new LoginResponse("access-token", "refresh-token", 42L, "USER"));

            mockMvc.perform(post("/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.accessToken").value("access-token"))
                    .andExpect(jsonPath("$.refreshToken").value("refresh-token"))
                    .andExpect(jsonPath("$.userId").value(42))
                    .andExpect(jsonPath("$.role").value("USER"));
        }

        @Test
        void refresh_shouldReturn200WithNewTokens() throws Exception {
            RefreshRequest request = new RefreshRequest("old-refresh-token");
            given(authService.refresh(any(RefreshRequest.class)))
                    .willReturn(new TokenResponse("new-access", "new-refresh"));

            mockMvc.perform(post("/auth/refresh")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.accessToken").value("new-access"))
                    .andExpect(jsonPath("$.refreshToken").value("new-refresh"));
        }

        @Test
        void logout_shouldReturn200() throws Exception {
            doNothing().when(authService).logout("test-token");

            mockMvc.perform(post("/auth/logout")
                            .header("Authorization", "Bearer test-token"))
                    .andExpect(status().isOk());
        }

        @Test
        void validate_shouldReturn200WithUserInfo() throws Exception {
            ValidateRequest request = new ValidateRequest("access-token");
            given(authService.validate(any(ValidateRequest.class)))
                    .willReturn(new ValidationResponse(42L, "ADMIN"));

            mockMvc.perform(post("/auth/validate")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.userId").value(42))
                    .andExpect(jsonPath("$.role").value("ADMIN"));
        }
    }

    @Nested
    class ValidationRejection {

        @Test
        void saveCredentials_blankEmail_shouldReturn400() throws Exception {
            SaveCredentialsRequest request = new SaveCredentialsRequest(1L, "", "password123");

            mockMvc.perform(post("/auth/credentials")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isBadRequest());
        }

        @Test
        void saveCredentials_shortPassword_shouldReturn400() throws Exception {
            SaveCredentialsRequest request = new SaveCredentialsRequest(1L, "user@example.com", "short");

            mockMvc.perform(post("/auth/credentials")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isBadRequest());
        }

        @Test
        void login_blankEmail_shouldReturn400() throws Exception {
            LoginRequest request = new LoginRequest("", "password123");

            mockMvc.perform(post("/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isBadRequest());
        }

        @Test
        void refresh_blankToken_shouldReturn400() throws Exception {
            RefreshRequest request = new RefreshRequest("");

            mockMvc.perform(post("/auth/refresh")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(objectMapper.writeValueAsString(request)))
                    .andExpect(status().isBadRequest());
        }
    }

    @Nested
    class BearerHeaderValidation {

        @Test
        void logout_malformedHeader_shouldReturn401() throws Exception {
            mockMvc.perform(post("/auth/logout")
                            .header("Authorization", "Basic dXNlcjpwYXNz"))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        void logout_missingBearerPrefix_shouldReturn401() throws Exception {
            mockMvc.perform(post("/auth/logout")
                            .header("Authorization", "raw-token-value"))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        void logout_missingHeader_shouldReturn401() throws Exception {
            mockMvc.perform(post("/auth/logout"))
                    .andExpect(status().isUnauthorized());
        }

        @Test
        void logout_emptyBearerToken_shouldReturn401() throws Exception {
            mockMvc.perform(post("/auth/logout")
                            .header("Authorization", "Bearer "))
                    .andExpect(status().isUnauthorized());
        }
    }
}

package com.innowise.authservice.service;

import com.innowise.authservice.service.dto.LoginRequest;
import com.innowise.authservice.service.dto.LoginResponse;
import com.innowise.authservice.service.dto.RefreshRequest;
import com.innowise.authservice.service.dto.SaveCredentialsRequest;
import com.innowise.authservice.service.dto.TokenResponse;
import com.innowise.authservice.service.dto.ValidateRequest;
import com.innowise.authservice.service.dto.ValidationResponse;

public interface AuthService {

    TokenResponse saveCredentials(SaveCredentialsRequest request);

    LoginResponse login(LoginRequest request);

    TokenResponse refresh(RefreshRequest request);

    void logout(String accessToken);

    ValidationResponse validate(ValidateRequest request);
}

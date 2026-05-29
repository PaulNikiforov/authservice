package com.innowise.authservice.model.dto;

public record TokenResponse(
        String accessToken,
        String refreshToken
) {
}

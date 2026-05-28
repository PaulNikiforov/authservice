package com.innowise.authservice.service.dto;

public record TokenResponse(
        String accessToken,
        String refreshToken
) {
}

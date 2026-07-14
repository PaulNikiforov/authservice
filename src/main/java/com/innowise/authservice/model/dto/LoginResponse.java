package com.innowise.authservice.model.dto;

public record LoginResponse(
        String accessToken,
        String refreshToken,
        Long userId,
        String role
) {
}

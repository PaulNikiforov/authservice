package com.innowise.authservice.service.dto;

public record LoginResponse(
        String accessToken,
        String refreshToken,
        Long userId,
        String role
) {
}

package com.innowise.authservice.service.dto;

public record ValidationResponse(
        Long userId,
        String role
) {
}

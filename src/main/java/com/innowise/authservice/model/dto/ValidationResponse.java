package com.innowise.authservice.model.dto;

public record ValidationResponse(
        Long userId,
        String role
) {
}

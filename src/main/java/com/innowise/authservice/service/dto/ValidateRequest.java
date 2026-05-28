package com.innowise.authservice.service.dto;

import jakarta.validation.constraints.NotBlank;

public record ValidateRequest(
        @NotBlank String accessToken
) {
}

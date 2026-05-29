package com.innowise.authservice.model.dto;

import jakarta.validation.constraints.NotBlank;

public record ValidateRequest(
        @NotBlank String accessToken
) {
}

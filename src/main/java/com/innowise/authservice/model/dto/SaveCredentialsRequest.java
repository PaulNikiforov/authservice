package com.innowise.authservice.model.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public record SaveCredentialsRequest(
        @NotNull Long userId,
        @NotBlank @Email String email,
        @NotBlank @Size(min = 8) String password
) {
}

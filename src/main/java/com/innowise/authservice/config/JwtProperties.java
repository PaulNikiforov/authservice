package com.innowise.authservice.config;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@ConfigurationProperties(prefix = "jwt")
@Validated
public record JwtProperties(
        @NotBlank String privateKey,
        @NotBlank String publicKey,
        @NotBlank String keyId,
        @Positive long accessExpiration,
        @Positive long refreshExpiration
) {
}

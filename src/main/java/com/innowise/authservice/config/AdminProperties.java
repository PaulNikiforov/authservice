package com.innowise.authservice.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@ConfigurationProperties(prefix = "admin")
public record AdminProperties(String email, String password, String userId) {
}

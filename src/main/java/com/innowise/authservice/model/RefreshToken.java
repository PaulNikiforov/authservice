package com.innowise.authservice.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Entity
@Table(name = "refresh_tokens")
@SequenceGenerator(name = "entity_seq", sequenceName = "refresh_tokens_id_seq", allocationSize = 50)
@Getter
@Setter(AccessLevel.NONE)
public class RefreshToken extends BaseEntity {

    @Column(name = "token_hash", unique = true, nullable = false)
    private String tokenHash;

    // No FK: userId belongs to User Service domain, not this service.
    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;

    public void setTokenHash(String tokenHash) { this.tokenHash = tokenHash; }
    public void setUserId(Long userId) { this.userId = userId; }
    public void setExpiresAt(LocalDateTime expiresAt) { this.expiresAt = expiresAt; }
}

package com.innowise.authservice.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

@Entity
@Table(name = "refresh_tokens")
@Getter
@Setter
@NoArgsConstructor
public class RefreshToken extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "refresh_tokens_id_gen")
    @SequenceGenerator(name = "refresh_tokens_id_gen", sequenceName = "refresh_tokens_id_seq", allocationSize = 50)
    @Column(name = "id", updatable = false, insertable = false)
    @Setter(AccessLevel.NONE)
    private Long id;

    @Column(name = "token_hash", unique = true, nullable = false, length = 64)
    private String tokenHash;

    // No FK: userId belongs to User Service domain, not this service.
    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;

    public static RefreshToken of(String tokenHash, Long userId, LocalDateTime expiresAt) {
        RefreshToken token = new RefreshToken();
        token.setTokenHash(tokenHash);
        token.setUserId(userId);
        token.setExpiresAt(expiresAt);
        return token;
    }
}

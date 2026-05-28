package com.innowise.authservice.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.LastModifiedDate;

import java.time.LocalDateTime;

@Entity
@Table(name = "credentials")
@SequenceGenerator(name = "entity_seq", sequenceName = "credentials_id_seq", allocationSize = 50)
@Getter
@Setter(AccessLevel.NONE)
public class Credential extends BaseEntity {

    public static final String DEFAULT_ROLE = "USER";

    @Column(name = "user_id", unique = true, nullable = false)
    private Long userId;

    @Column(name = "email", unique = true, nullable = false)
    private String email;

    @Column(name = "password_hash", nullable = false)
    private String passwordHash;

    @Column(name = "role", nullable = false, length = 20)
    private String role = DEFAULT_ROLE;

    @Column(name = "is_active", nullable = false)
    private Boolean isActive = true;

    @LastModifiedDate
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    // updated_at is set by JPA auditing — must not be mutated externally
    // but JPA needs field-level access, so no @Setter override needed here
    // (class-level @Setter(NONE) already blocks Lombok setters)

    public void setUserId(Long userId) { this.userId = userId; }
    public void setEmail(String email) { this.email = email; }
    public void setPasswordHash(String passwordHash) { this.passwordHash = passwordHash; }
    public void setRole(String role) { this.role = role; }
    public void setIsActive(Boolean isActive) { this.isActive = isActive; }
}

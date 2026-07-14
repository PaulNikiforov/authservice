package com.innowise.authservice.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.data.annotation.LastModifiedDate;

import java.time.LocalDateTime;

@Entity
@Table(name = "credentials")
@Getter
@Setter
@NoArgsConstructor
@EqualsAndHashCode(of = {"userId"})
public class Credential extends BaseEntity {

    public static final String DEFAULT_ROLE = "USER";
    public static final String ROLE_ADMIN = "ADMIN";

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "credentials_id_gen")
    @SequenceGenerator(name = "credentials_id_gen", sequenceName = "credentials_id_seq", allocationSize = 50)
    @Column(name = "id", updatable = false, insertable = false)
    @Setter(AccessLevel.NONE)
    private Long id;

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
    @Setter(AccessLevel.NONE)
    private LocalDateTime updatedAt;

    public static Credential of(Long userId, String email, String passwordHash, String role) {
        Credential credential = new Credential();
        credential.setUserId(userId);
        credential.setEmail(email);
        credential.setPasswordHash(passwordHash);
        credential.setRole(role);
        return credential;
    }
}

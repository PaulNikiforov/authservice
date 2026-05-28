package com.innowise.authservice.repository;

import com.innowise.authservice.model.Credential;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface CredentialRepository extends JpaRepository<Credential, Long> {

    Optional<Credential> findByEmail(String email);

    Optional<Credential> findByUserId(Long userId);

    boolean existsByEmail(String email);
}

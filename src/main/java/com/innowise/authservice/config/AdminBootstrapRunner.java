package com.innowise.authservice.config;

import com.innowise.authservice.model.Credential;
import com.innowise.authservice.repository.CredentialRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class AdminBootstrapRunner implements ApplicationRunner {

    private final CredentialRepository credentialRepository;
    private final PasswordEncoder passwordEncoder;
    private final String adminEmail;
    private final String adminPassword;
    private final String adminUserId;

    public AdminBootstrapRunner(CredentialRepository credentialRepository,
                                PasswordEncoder passwordEncoder,
                                AdminProperties adminProperties) {
        this.credentialRepository = credentialRepository;
        this.passwordEncoder = passwordEncoder;
        this.adminEmail = adminProperties.email();
        this.adminPassword = adminProperties.password();
        this.adminUserId = adminProperties.userId();
    }

    @Override
    public void run(ApplicationArguments args) {
        boolean emailSet = isSet(adminEmail);
        boolean passwordSet = isSet(adminPassword);
        boolean userIdSet = isSet(adminUserId);

        if (!emailSet && !passwordSet && !userIdSet) {
            log.info("Admin bootstrap disabled: ADMIN_EMAIL/ADMIN_PASSWORD/ADMIN_USER_ID not set");
            return;
        }
        if (!(emailSet && passwordSet && userIdSet)) {
            throw new IllegalStateException(
                    "Admin bootstrap misconfigured: ADMIN_EMAIL, ADMIN_PASSWORD and ADMIN_USER_ID "
                            + "must all be set, or all be empty");
        }

        long userId;
        try {
            userId = Long.parseLong(adminUserId.trim());
        } catch (NumberFormatException e) {
            throw new IllegalStateException(
                    "Admin bootstrap misconfigured: ADMIN_USER_ID must be numeric, got: " + adminUserId, e);
        }

        if (credentialRepository.existsByEmail(adminEmail)) {
            log.info("Admin bootstrap skipped: credential already exists for {}", adminEmail);
            return;
        }

        Credential admin = Credential.of(userId, adminEmail,
                passwordEncoder.encode(adminPassword), Credential.ROLE_ADMIN);
        try {
            credentialRepository.save(admin);
            log.info("Admin user created: email={}, userId={}", adminEmail, userId);
        } catch (DataIntegrityViolationException e) {
            log.info("Admin bootstrap skipped: created concurrently by another instance ({})", adminEmail);
        }
    }

    private static boolean isSet(String value) {
        return value != null && !value.isBlank();
    }
}

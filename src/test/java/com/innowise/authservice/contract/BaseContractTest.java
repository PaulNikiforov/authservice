package com.innowise.authservice.contract;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.innowise.authservice.AuthserviceApplication;
import com.innowise.authservice.TestcontainersConfiguration;
import com.innowise.authservice.repository.CredentialRepository;
import com.innowise.authservice.repository.RefreshTokenRepository;
import io.restassured.module.mockmvc.RestAssuredMockMvc;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest(classes = AuthserviceApplication.class)
@AutoConfigureMockMvc
@Import(TestcontainersConfiguration.class)
public abstract class BaseContractTest {

    static final long   CONTRACT_USER_ID = 999L;
    static final String CONTRACT_EMAIL   = "contract@gateway.com";
    static final String CONTRACT_PASS    = "ContractPass1!";

    @Autowired
    protected MockMvc mockMvc;

    @Autowired
    protected ObjectMapper objectMapper;

    @Autowired
    private CredentialRepository credentialRepository;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @BeforeEach
    void setUp() {
        refreshTokenRepository.deleteAll();
        credentialRepository.deleteAll();

        RestAssuredMockMvc.mockMvc(mockMvc);
    }
}

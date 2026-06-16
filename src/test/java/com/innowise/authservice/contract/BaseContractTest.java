package com.innowise.authservice.contract;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.innowise.authservice.TestcontainersConfiguration;
import com.innowise.authservice.model.dto.SaveCredentialsRequest;
import com.innowise.authservice.repository.CredentialRepository;
import com.innowise.authservice.repository.RefreshTokenRepository;
import io.restassured.module.mockmvc.RestAssuredMockMvc;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Base class for SCC-generated provider verification tests in auth-service.
 *
 * <p>Creates a known credential in {@code setUp()} so that login and credentials
 * contracts can succeed against a real database. The email/password here MUST
 * match the concrete values used in the corresponding {@code .groovy} contract files.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Import(TestcontainersConfiguration.class)
public abstract class BaseContractTest {

    static final long   CONTRACT_USER_ID = 999L;
    static final String CONTRACT_EMAIL   = "contract@gateway.com";
    static final String CONTRACT_PASS    = "ContractPass1!";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private CredentialRepository credentialRepository;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @BeforeEach
    void setUp() throws Exception {
        refreshTokenRepository.deleteAll();
        credentialRepository.deleteAll();

        String body = objectMapper.writeValueAsString(
                new SaveCredentialsRequest(CONTRACT_USER_ID, CONTRACT_EMAIL, CONTRACT_PASS));

        mockMvc.perform(post("/api/v1/auth/credentials")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isCreated());

        RestAssuredMockMvc.mockMvc(mockMvc);
    }
}

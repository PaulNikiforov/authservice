package com.innowise.authservice.contract;

import com.innowise.authservice.model.dto.SaveCredentialsRequest;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.http.MediaType;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public abstract class BaseLoginContractTest extends BaseContractTest {

    @BeforeEach
    void seedLoginCredential() throws Exception {
        String body = objectMapper.writeValueAsString(
                new SaveCredentialsRequest(CONTRACT_USER_ID, CONTRACT_EMAIL, CONTRACT_PASS));

        mockMvc.perform(post("/api/v1/auth/credentials")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isCreated());
    }
}

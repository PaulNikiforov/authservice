// FILE: src/test/java/com/innowise/authservice/controller/JwksControllerTest.java
package com.innowise.authservice.controller;

import com.innowise.authservice.config.SecurityConfig;
import com.innowise.authservice.security.CustomAccessDeniedHandler;
import com.innowise.authservice.security.CustomAuthenticationEntryPoint;
import com.innowise.authservice.service.JwtService;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Jwks;
import io.jsonwebtoken.security.JwkSet;
import io.jsonwebtoken.security.RsaPublicJwk;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;

import static org.mockito.BDDMockito.given;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(JwksController.class)
@Import(SecurityConfig.class)
class JwksControllerTest {

    private static final String KEY_ID = "test-key-1";

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private JwtService jwtService;

    @MockitoBean
    private CustomAuthenticationEntryPoint authenticationEntryPoint;

    @MockitoBean
    private CustomAccessDeniedHandler accessDeniedHandler;

    @Test
    void getJwks_withoutAuthentication_shouldReturn200WithJwkSet() throws Exception {
        KeyPair keyPair = Jwts.SIG.RS256.keyPair().build();
        RsaPublicJwk jwk = Jwks.builder()
                .key((RSAPublicKey) keyPair.getPublic())
                .id(KEY_ID)
                .algorithm("RS256")
                .publicKeyUse("sig")
                .build();
        JwkSet jwkSet = Jwks.set().add(jwk).build();

        given(jwtService.getJwkSet()).willReturn(jwkSet);

        mockMvc.perform(get("/oauth2/jwks"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys").isArray())
                .andExpect(jsonPath("$.keys.length()").value(1))
                .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
                .andExpect(jsonPath("$.keys[0].use").value("sig"))
                .andExpect(jsonPath("$.keys[0].alg").value("RS256"))
                .andExpect(jsonPath("$.keys[0].kid").value(KEY_ID))
                .andExpect(jsonPath("$.keys[0].n").exists())
                .andExpect(jsonPath("$.keys[0].e").exists());
    }
}

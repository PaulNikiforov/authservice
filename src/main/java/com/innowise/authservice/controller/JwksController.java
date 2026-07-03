package com.innowise.authservice.controller;

import com.innowise.authservice.service.JwtService;
import io.jsonwebtoken.jackson.io.JacksonSerializer;
import io.jsonwebtoken.security.JwkSet;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Publishes the service's RSA public key as a JWK Set so resource servers can validate
 * access tokens locally. jjwt's {@link JwkSet} embeds internal supplier wrappers that a
 * generic Jackson {@code ObjectMapper} cannot serialize, so it is serialized explicitly
 * via jjwt's own {@link JacksonSerializer} rather than returned as the response body directly.
 */
@RestController
@RequiredArgsConstructor
@Tag(name = "JWKS", description = "Public key discovery for JWT verification")
public class JwksController {

    private final JwtService jwtService;
    private final JacksonSerializer<JwkSet> jwkSetSerializer = new JacksonSerializer<>();

    @GetMapping("/oauth2/jwks")
    @Operation(summary = "Get the JWK Set used to verify access tokens")
    public ResponseEntity<byte[]> getJwks() {
        byte[] body = jwkSetSerializer.serialize(jwtService.getJwkSet());
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON).body(body);
    }
}

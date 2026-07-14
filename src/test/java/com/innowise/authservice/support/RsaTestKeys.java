package com.innowise.authservice.support;

import io.jsonwebtoken.Jwts;

import java.security.Key;
import java.security.KeyPair;
import java.util.Base64;

public final class RsaTestKeys {

    private RsaTestKeys() {
    }

    public record Pair(KeyPair keyPair, String privateKeyPem, String publicKeyPem) {
    }

    public static Pair generate() {
        KeyPair keyPair = Jwts.SIG.RS256.keyPair().build();
        return new Pair(keyPair, toPem(keyPair.getPrivate(), "PRIVATE KEY"), toPem(keyPair.getPublic(), "PUBLIC KEY"));
    }

    private static String toPem(Key key, String label) {
        String base64 = Base64.getEncoder().encodeToString(key.getEncoded());
        StringBuilder pem = new StringBuilder();
        pem.append("-----BEGIN ").append(label).append("-----\n");
        for (int i = 0; i < base64.length(); i += 64) {
            pem.append(base64, i, Math.min(i + 64, base64.length())).append('\n');
        }
        pem.append("-----END ").append(label).append("-----\n");
        return pem.toString();
    }
}

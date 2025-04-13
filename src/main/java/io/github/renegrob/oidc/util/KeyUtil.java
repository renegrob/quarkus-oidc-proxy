package io.github.renegrob.oidc.util;

import java.security.PublicKey;
import java.util.Base64;

public final class KeyUtil {

    private KeyUtil() {
        // Prevent instantiation
    }

    public static String publicKeyToPem(PublicKey publicKey) {
        String encodedKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        return "-----BEGIN PUBLIC KEY-----\n" + encodedKey + "\n-----END PUBLIC KEY-----";
    }
}

package io.github.renegrob.oidc.util;

import io.github.renegrob.oidc.config.OAuthConfig;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PublicKey;
import java.util.Base64;

public final class KeyUtil {

    private KeyUtil() {
        // Prevent instantiation
    }

    /**
     * Resolves the private key from either the direct content or file path
     * @param config the key configuration
     * @return the key content
     * @throws IllegalStateException if neither key content nor a valid path is provided
     */
    public static String resolvePrivateKey(OAuthConfig.KeyConfig config) {
        if (config.privateKey().isPresent()) {
            return config.privateKey().get();
        } else if (config.privateKeyLocation().isPresent()) {
            try {
                return readKeyFromFile(config.privateKeyLocation().get());
            } catch (IOException e) {
                throw new IllegalStateException("Failed to read private key from path: " + config.privateKeyLocation().get(), e);
            }
        }
        throw new IllegalStateException("Neither private-key nor private-key-path is configured");
    }

    /**
     * Resolves the public key from either the direct content or file path
     * @param config the key configuration
     * @return the key content
     * @throws IllegalStateException if neither key content nor a valid path is provided
     */
    public static String resolvePublicKey(OAuthConfig.KeyConfig config) {
        if (config.publicKey().isPresent()) {
            return config.publicKey().get();
        } else if (config.publicKeyLocation().isPresent()) {
            try {
                return readKeyFromFile(config.publicKeyLocation().get());
            } catch (IOException e) {
                throw new IllegalStateException("Failed to read public key from path: " + config.publicKeyLocation().get(), e);
            }
        }
        throw new IllegalStateException("Neither public-key nor public-key-path is configured");
    }

    private static String readKeyFromFile(String filePath) throws IOException {
        Path path = Paths.get(filePath);
        return Files.readString(path).trim();
    }

    public static String publicKeyToPem(PublicKey publicKey) {
        String encodedKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        return "-----BEGIN PUBLIC KEY-----\n" + encodedKey + "\n-----END PUBLIC KEY-----";
    }
}

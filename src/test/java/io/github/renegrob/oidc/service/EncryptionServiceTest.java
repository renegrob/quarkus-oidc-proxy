package io.github.renegrob.oidc.service;

import io.github.renegrob.oidc.config.OAuthConfig;
import io.github.renegrob.oidc.util.Base64Util;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class EncryptionServiceTest {

    private EncryptionService encryptionService;
    private OAuthConfig.CookieConfig cookieConfig;
    private RandomService randomService;

    @BeforeEach
    void setUp() {
        // Mock dependencies
        OAuthConfig config = mock(OAuthConfig.class);
        cookieConfig = mock(OAuthConfig.CookieConfig.class);
        randomService = mock(RandomService.class);

        when(config.cookie()).thenReturn(cookieConfig);
        when(cookieConfig.encryptionKey()).thenReturn("zgjdFQxRYPXizuRG5UsJh9eEG3lbqn7qu5WB6KOoofw="); // Mock key
        when(cookieConfig.encryptionAlgorithm()).thenReturn("AES/GCM/NoPadding");

        encryptionService = new EncryptionService(config, randomService);
        encryptionService.init();
    }

    @Test
    void testEncryptAndDecrypt() throws Exception {
        String plainText = "Hello, World!";
        byte[] mockIv = new byte[12];
        new Random().nextBytes(mockIv);

        when(randomService.randomBytes(12)).thenReturn(mockIv);

        // Encrypt
        String encryptedText = encryptionService.encrypt(plainText);
        assertNotNull(encryptedText);

        // Decrypt
        String decryptedText = encryptionService.decrypt(encryptedText);
        assertEquals(plainText, decryptedText);
    }

    @Test
    void testDecryptWithInvalidData() {
        String invalidData = "invalidEncryptedText";

        assertThrows(Exception.class, () -> encryptionService.decrypt(invalidData));
    }
}
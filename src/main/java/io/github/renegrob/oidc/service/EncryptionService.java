package io.github.renegrob.oidc.service;

import io.github.renegrob.oidc.config.OAuthConfig;
import io.github.renegrob.oidc.util.Base64Util;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

@ApplicationScoped
@SuppressWarnings("unused")
public class EncryptionService {

    private static final int IV_SIZE = 12; // Recommended size for GCM
    private static final int TAG_LENGTH = 128; // Authentication tag length in bits

    private final OAuthConfig.CookieConfig config;
    private final RandomService randomService;
    private SecretKeySpec secretKey;

    @Inject
    public EncryptionService(OAuthConfig config, RandomService randomService) {
        this.config = config.cookie();
        this.randomService = randomService;
    }

    @PostConstruct
    void init() {
        String base64Key = config.encryptionKey();
        byte[] decodedKey = Base64Util.base64ToBytes(base64Key);
        this.secretKey = new SecretKeySpec(decodedKey, "AES");
        try {
            createCipher(Cipher.ENCRYPT_MODE, new byte[12]);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
    }

    public String encrypt(String plainText) throws Exception {
        byte[] iv = randomService.randomBytes(IV_SIZE);
        Cipher cipher = createCipher(Cipher.ENCRYPT_MODE, iv);

        byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        byte[] encryptedData = new byte[iv.length + cipherText.length];
        System.arraycopy(iv, 0, encryptedData, 0, iv.length);
        System.arraycopy(cipherText, 0, encryptedData, iv.length, cipherText.length);

        return Base64Util.toUrlBase64(encryptedData);
    }

    public String decrypt(String encryptedText) throws Exception {
        byte[] encryptedData = Base64.getUrlDecoder().decode(encryptedText);
        byte[] iv = new byte[IV_SIZE];
        System.arraycopy(encryptedData, 0, iv, 0, IV_SIZE);

        Cipher cipher = createCipher(Cipher.DECRYPT_MODE, iv);

        byte[] cipherText = new byte[encryptedData.length - IV_SIZE];
        System.arraycopy(encryptedData, IV_SIZE, cipherText, 0, cipherText.length);

        byte[] plainText = cipher.doFinal(cipherText);
        return new String(plainText, StandardCharsets.UTF_8);
    }

    private Cipher createCipher(int mode, byte[] iv) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        GCMParameterSpec parameterSpec = new GCMParameterSpec(TAG_LENGTH, iv);
        Cipher cipher = Cipher.getInstance(config.encryptionAlgorithm());
        cipher.init(mode, secretKey, parameterSpec);
        return cipher;
    }
}
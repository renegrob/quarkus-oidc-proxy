package io.github.renegrob.oidc.service.internalissuer;

import io.github.renegrob.oidc.config.FederationMode;
import io.github.renegrob.oidc.config.OAuthConfig;
import io.github.renegrob.oidc.util.HashBuilder;
import io.github.renegrob.oidc.util.KeyUtil;
import io.smallrye.jwt.util.KeyUtils;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;

@Singleton
public class InternalKeyInfo {

    private static final Logger LOG = LoggerFactory.getLogger(InternalKeyInfo.class);

    private final PublicKey publicKey;
    private final String keyId;
    private final PrivateKey privateKey;

    @Inject
    InternalKeyInfo(OAuthConfig config) {
        if (config.federationMode() == FederationMode.PASS_THROUGH) {
            LOG.info("Internal issuer is disabled");
            this.publicKey = null;
            this.keyId = null;
            this.privateKey = null;
            return;
        }
        var keyConfig = config.internalIssuer().keyConfig();
        try {
            this.publicKey = KeyUtils.decodePublicKey(KeyUtil.resolvePublicKey(keyConfig), keyConfig.signatureAlgorithm());
            this.privateKey = KeyUtils.decodePrivateKey(KeyUtil.resolvePrivateKey(keyConfig), keyConfig.signatureAlgorithm());
        } catch (GeneralSecurityException e) {
            LOG.error("Failed to decode key: {}", e.getMessage(), e);
            throw new RuntimeException(e);
        }
        keyId = keyConfig.keyId().orElseGet(() -> toKeyId(publicKey));
    }

    public String keyId() {
        return keyId;
    }

    public PrivateKey privateKey() {
        return privateKey;
    }

    public PublicKey publicKey() {
        return publicKey;
    }

    private static String toKeyId(PublicKey publicKey) {
        return HashBuilder.sha256(publicKey.getEncoded()).toUrlSafeBase64().substring(0, 12);
    }
}

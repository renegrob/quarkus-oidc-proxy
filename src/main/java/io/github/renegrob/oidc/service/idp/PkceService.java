package io.github.renegrob.oidc.service.idp;

import io.github.renegrob.oidc.config.OAuthConfig;
import io.github.renegrob.oidc.config.PkceMethod;
import io.github.renegrob.oidc.service.CookieService;
import io.github.renegrob.oidc.service.RandomService;
import io.github.renegrob.oidc.util.Base64Util;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static io.github.renegrob.oidc.constants.CookieNames.OAUTH_CODE_VERIFIER;

@ApplicationScoped
public class PkceService {
    private static final Logger LOG = LoggerFactory.getLogger(PkceService.class);

    private final OAuthConfig.FederatedClientConfig clientConfig;
    private final RandomService randomService;
    private final CookieService cookieService;

    @Inject
    public PkceService(OAuthConfig config, RandomService randomService, CookieService cookieService) {
        this.clientConfig = config.provider().client();
        this.randomService = randomService;
        this.cookieService = cookieService;
    }

    public PkceData generatePkceData() {
        if (clientConfig.pkceMethod().isEmpty()) {
            return null;
        }

        // Generate code verifier
        byte[] randomBytes = randomService.randomBytes(32);
        String codeVerifier = Base64Util.toBase64(randomBytes, true)
                .replace("+", "-")
                .replace("/", "_")
                .replace("=", "");

        // Generate code challenge
        String codeChallenge = generateCodeChallenge(codeVerifier, clientConfig.pkceMethod().get());

        return new PkceData(
                clientConfig.pkceMethod().get(),
                codeVerifier,
                codeChallenge,
                cookieService.createSessionCookie(OAUTH_CODE_VERIFIER, codeVerifier)
        );
    }

    private String generateCodeChallenge(String codeVerifier, PkceMethod method) {
        if (method == PkceMethod.PLAIN) {
            return codeVerifier;
        }

        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.UTF_8));
            return Base64Util.toUrlBase64(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to generate code challenge", e);
        }
    }

    public record PkceData(PkceMethod method, String codeVerifier, String codeChallenge, jakarta.ws.rs.core.NewCookie cookie) {}
} 
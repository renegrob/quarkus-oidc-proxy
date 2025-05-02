package io.github.renegrob.oidc.service.idp;

import io.github.renegrob.oidc.config.OAuthConfig;
import io.github.renegrob.oidc.service.CookieService;
import io.github.renegrob.oidc.service.RandomService;
import io.github.renegrob.oidc.util.Base64Util;
import io.github.renegrob.oidc.util.HashBuilder;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import jakarta.ws.rs.BadRequestException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;

import static io.github.renegrob.oidc.constants.CookieNames.OAUTH_STATE;

@Singleton
public class GrantRequestVerificationService {

    private static final Logger LOG = LoggerFactory.getLogger(GrantRequestVerificationService.class);

    private final RandomService randomService;
    private final CookieService cookieService;
    private final OAuthConfig config;

    @Inject
    public GrantRequestVerificationService(RandomService randomService, OAuthConfig config, CookieService cookieService) {
        this.randomService = randomService;
        this.config = config;
        this.cookieService = cookieService;
    }

    public GrantRequestValidationData createStateCookie(String requestUri) {
        String state = Base64Util.toBase64(randomService.randomBytes(32), true)
                + (requestUri != null ? ":" + requestUri : "");
        var stateHash = createStateHash(state);
        return new GrantRequestValidationData(state, cookieService.createSessionCookie(OAUTH_STATE, stateHash));
    }

    public void verifyState(String state, String cookieState) {
        if (state == null) {
            throw new BadRequestException("Missing state");
        }
        if (cookieState == null) {
            throw new BadRequestException("Missing cookie");
        }
        String stateHash = createStateHash(state);
        LOG.debug("verifying stateHash: '{}' against cookieState: '{}'", stateHash, cookieState);
        if (!stateHash.equals(cookieState)) {
            throw new BadRequestException("State mismatch");
        }
    }

    public static URI extractRequestUri(String state) {
        if (state != null) {
            String[] parts = state.split(":", 2);
            if (parts.length == 2) {
                return URI.create(parts[1]);
            }
        }
        return URI.create("/");
    }

    private String createStateHash(String state) {
        return HashBuilder.sha512(config.provider().client().stateSecret()).update(state).toBase64(true);
    }
}

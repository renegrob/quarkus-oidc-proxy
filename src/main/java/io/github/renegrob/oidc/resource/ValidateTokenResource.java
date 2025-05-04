package io.github.renegrob.oidc.resource;

import io.github.renegrob.oidc.config.FederationMode;
import io.github.renegrob.oidc.config.OAuthConfig;
import io.github.renegrob.oidc.service.CookieService;
import io.github.renegrob.oidc.service.internalissuer.InternalJwtValidatorService;
import io.github.renegrob.oidc.service.idp.ExternalJwtValidatorService;
import io.quarkus.runtime.util.StringUtil;
import io.smallrye.common.annotation.RunOnVirtualThread;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import org.jboss.resteasy.reactive.RestCookie;
import org.jboss.resteasy.reactive.RestResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static io.github.renegrob.oidc.config.TokenForwardingMethod.BEARER;

@Path("/auth/validate")
@SuppressWarnings("unused")
public class ValidateTokenResource {
    private static final Logger LOG = LoggerFactory.getLogger(ValidateTokenResource.class);

    @Inject
    CookieService cookieService;

    @Inject
    OAuthConfig config;

    @Inject
    InternalJwtValidatorService internalJwtValidatorService;

    @Inject
    ExternalJwtValidatorService externalJwtValidatorService;


    @GET
    @RunOnVirtualThread
    public RestResponse<String> validate(@RestCookie("AUTH_TOKEN") String encryptedToken) {
        if (StringUtil.isNullOrEmpty(encryptedToken)) {
            LOG.debug("No auth token found in cookie");
            return RestResponse.status(Response.Status.UNAUTHORIZED);
        }
        String token = cookieService.decryptAuthCookie(encryptedToken);

        boolean tokenIsValid = config.federationMode() == FederationMode.PASS_THROUGH
                ? externalJwtValidatorService.validateToken(token)
                : internalJwtValidatorService.validateToken(token);
        if (tokenIsValid) {
            LOG.debug("Token is valid");
            String headerName = config.token().forwardingMethod() == BEARER ? HttpHeaders.AUTHORIZATION : config.token().headerName();
            String headerPrefix = config.token().forwardingMethod() == BEARER ? "Bearer " : "";
            String headerValue = headerPrefix + token;
            LOG.debug("Setting header: {}: {}<JWT-Token>", headerName, headerPrefix);
            RestResponse.ResponseBuilder<String> responseBuilder = RestResponse.ResponseBuilder
                    .ok("Token is valid")
                    .header(headerName, headerValue);
            return responseBuilder.build();
        } else {
            LOG.debug("Token is invalid or expired");
            return RestResponse.status(Response.Status.UNAUTHORIZED);
        }
    }
}
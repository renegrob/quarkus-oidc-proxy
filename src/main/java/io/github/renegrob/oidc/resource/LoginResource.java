package io.github.renegrob.oidc.resource;

import io.github.renegrob.oidc.service.idp.GrantRequestVerificationService;
import io.github.renegrob.oidc.service.idp.IdpConfiguration;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;

/**
 * This resource handles the login request by redirecting the user to the authorization endpoint of the identity provider.
 * It creates a state cookie to prevent CSRF attacks and includes it in the response.
 */
@Path("/auth/login")
public class LoginResource {

    private static final Logger LOG = LoggerFactory.getLogger(LoginResource.class);

    @Inject
    IdpConfiguration config;

    @Inject
    GrantRequestVerificationService grantRequestVerificationService;

    @GET
    @Produces(MediaType.TEXT_HTML)
    public Response login(@QueryParam("rd") String requestUri) {
        var validationData = grantRequestVerificationService.createStateCookie(requestUri);

        URI redirectUri = UriBuilder
                .fromUri(config.authorizationEndpoint())
                .queryParam("client_id", config.clientId())
                .queryParam("response_type", "code")
                .queryParam("redirect_uri", config.redirectUri())
                .queryParam("response_mode", "query")
                .queryParam("scope", config.scope())
                .queryParam("state", validationData.state())
                .build();
        LOG.debug("Setting cookie: {}", validationData.cookie());
        return Response.seeOther(redirectUri).cookie(validationData.cookie()).build();
    }
}

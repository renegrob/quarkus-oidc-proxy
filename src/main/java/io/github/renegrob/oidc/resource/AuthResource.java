package io.github.renegrob.oidc.resource;

import io.github.renegrob.oidc.config.OAuthConfig;
import io.github.renegrob.oidc.service.*;
import io.github.renegrob.oidc.service.idp.DiscoveryService;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.NewCookie;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.jboss.resteasy.reactive.RestCookie;
import org.jboss.resteasy.reactive.RestResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.util.Map;

import static io.github.renegrob.oidc.service.idp.EndpointType.*;

@Path("/authOld")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
@SuppressWarnings("unused")
public class AuthResource {
    private static final Logger LOG = LoggerFactory.getLogger(AuthResource.class);

    @Inject
    CookieService cookieService;

    @Inject
    OAuthConfig config;

    @Inject
    DiscoveryService discoveryService;


    @GET
    @Path("/logout")
    public RestResponse<Void> logout() {
        LOG.debug("Processing logout request");
        NewCookie logoutCookie = cookieService.createLogoutCookie();

        // Try to get end session endpoint from discovery
        String endSessionEndpoint = discoveryService.getEndpoint(END_SESSION_ENDPOINT);
        if (endSessionEndpoint != null) {
            LOG.debug("Redirecting to provider end session endpoint: {}", endSessionEndpoint);
            return RestResponse.ResponseBuilder.<Void>create(Response.Status.FOUND)
                    .location(URI.create(endSessionEndpoint))
                    .cookie(logoutCookie)
                    .build();
        } else {
            LOG.debug("No end session endpoint found, logging out locally only");
            return RestResponse.ResponseBuilder.<Void>create(Response.Status.FOUND)
                    .location(URI.create("/"))
                    .cookie(logoutCookie)
                    .build();
        }
    }



//    @GET
//    @Path("/discovery")
//    public RestResponse<Map<String, String>> getDiscoveryInfo() {
//        Map<String, String> discoveryInfo = Map.of(
//                "issuer", discoveryService.getEndpoint(ISSUER) != null ? discoveryService.getEndpoint("issuer") : "Not configured",
//                "authorization_endpoint", discoveryService.getEndpoint(AUTHORIZATION_ENDPOINT) != null ? discoveryService.getEndpoint("authorization_endpoint") : "Not configured",
//                "token_endpoint", discoveryService.getEndpoint("token_endpoint") != null ? discoveryService.getEndpoint("token_endpoint") : "Not configured",
//                "userinfo_endpoint", discoveryService.getEndpoint("userinfo_endpoint") != null ? discoveryService.getEndpoint("userinfo_endpoint") : "Not configured",
//                "jwks_uri", discoveryService.getEndpoint("jwks_uri") != null ? discoveryService.getEndpoint("jwks_uri") : "Not configured",
//                "end_session_endpoint", discoveryService.getEndpoint("end_session_endpoint") != null ? discoveryService.getEndpoint("end_session_endpoint") : "Not configured",
//                "callback_path", redirectPath
//        );
//
//        return RestResponse.ok(discoveryInfo);
//    }


}
package io.github.renegrob.oauth2proxy.resource;

import io.github.renegrob.oauth2proxy.config.OAuthConfig;
import io.github.renegrob.oauth2proxy.service.CookieService;
import io.github.renegrob.oauth2proxy.service.DiscoveryService;
import io.github.renegrob.oauth2proxy.service.JwtService;
import io.quarkus.oidc.IdToken;
import io.quarkus.oidc.RefreshToken;
import io.quarkus.security.Authenticated;
import io.quarkus.security.credential.TokenCredential;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.NewCookie;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.jboss.resteasy.reactive.RestCookie;
import org.jboss.resteasy.reactive.RestResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.util.Map;

@Path("/auth")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
@SuppressWarnings("unused")
public class AuthResource {
    private static final Logger LOG = LoggerFactory.getLogger(AuthResource.class);

    @Inject
    @IdToken
    JsonWebToken idToken;

//    @Inject
//    RefreshToken refreshToken;

    @Inject
    CookieService cookieService;

    @Inject
    OAuthConfig config;

    @Inject
    JwtService jwtService;

    @Inject
    DiscoveryService discoveryService;

    @ConfigProperty(name = "quarkus.oidc.authentication.redirect-path")
    String redirectPath;

    @GET
    @Path("/callback")
    public RestResponse<Void> callback() {
        try {
            String token = idToken.getRawToken();
            LOG.debug("Received ID token in callback");

            NewCookie authCookie = cookieService.createAuthCookie(token);

            return RestResponse.ResponseBuilder.<Void>create(Response.Status.FOUND)
                    .location(URI.create("/"))
                    .cookie(authCookie)
                    .build();
        } catch (Exception e) {
            LOG.error("Error in callback endpoint", e);
            return RestResponse.status(Response.Status.INTERNAL_SERVER_ERROR);
        }
    }

    @GET
    @Path("/validate")
    public RestResponse<Void> validate(@RestCookie("AUTH_TOKEN") String token) {
        if (token == null || token.isEmpty()) {
            LOG.debug("No auth token found in cookie");
            return RestResponse.status(Response.Status.UNAUTHORIZED);
        }

        if (cookieService.isValidToken(token)) {
            LOG.debug("Token is valid");
            RestResponse.ResponseBuilder<Void> responseBuilder = RestResponse.ResponseBuilder.<Void>ok()
                    .header(config.jwt().headerName(), token);

            // Extract claims and pass them through as headers if configured
            if (config.jwt().passThroughHeaders()) {
                Map<String, Object> claims = jwtService.extractClaims(token);

                for (Map.Entry<String, Object> entry : claims.entrySet()) {
                    String claimName = entry.getKey();
                    Object claimValue = entry.getValue();

                    // Skip standard JWT claims we already handle
                    if (claimName.equals(config.jwt().subjectKey()) ||
                            claimName.equals(config.jwt().issuerKey()) ||
                            claimName.equals(config.jwt().expirationKey())) {
                        continue;
                    }

                    // For arrays/lists, join with commas
                    if (claimValue instanceof Iterable) {
                        StringBuilder sb = new StringBuilder();
                        boolean first = true;
                        for (Object item : (Iterable<?>) claimValue) {
                            if (!first) {
                                sb.append(",");
                            }
                            sb.append(item);
                            first = false;
                        }
                        responseBuilder.header(config.jwt().claimToHeaderPrefix() + claimName, sb.toString());
                    } else {
                        responseBuilder.header(config.jwt().claimToHeaderPrefix() + claimName, claimValue.toString());
                    }
                }
            }

            return responseBuilder.build();
        } else {
            LOG.debug("Token is invalid or expired");
            return RestResponse.status(Response.Status.UNAUTHORIZED);
        }
    }

    @GET
    @Path("/logout")
    public RestResponse<Void> logout() {
        LOG.debug("Processing logout request");
        NewCookie logoutCookie = cookieService.createLogoutCookie();

        // Try to get end session endpoint from discovery
        String endSessionEndpoint = discoveryService.getEndpoint("end_session_endpoint");
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

    @Authenticated
    @GET
    @Path("/login")
    public RestResponse<Void> login() {
        LOG.debug("Logged in as {}", idToken.getSubject());
        // This endpoint will trigger the OIDC authentication flow
        // The actual redirect is handled by Quarkus OIDC extension
        return RestResponse.ok();
    }

    @GET
    @Path("/discovery")
    public RestResponse<Map<String, String>> getDiscoveryInfo() {
        Map<String, String> discoveryInfo = Map.of(
                "issuer", discoveryService.getEndpoint("issuer") != null ? discoveryService.getEndpoint("issuer") : "Not configured",
                "authorization_endpoint", discoveryService.getEndpoint("authorization_endpoint") != null ? discoveryService.getEndpoint("authorization_endpoint") : "Not configured",
                "token_endpoint", discoveryService.getEndpoint("token_endpoint") != null ? discoveryService.getEndpoint("token_endpoint") : "Not configured",
                "userinfo_endpoint", discoveryService.getEndpoint("userinfo_endpoint") != null ? discoveryService.getEndpoint("userinfo_endpoint") : "Not configured",
                "jwks_uri", discoveryService.getEndpoint("jwks_uri") != null ? discoveryService.getEndpoint("jwks_uri") : "Not configured",
                "end_session_endpoint", discoveryService.getEndpoint("end_session_endpoint") != null ? discoveryService.getEndpoint("end_session_endpoint") : "Not configured",
                "callback_path", redirectPath
        );

        return RestResponse.ok(discoveryInfo);
    }


}
package com.example.oauth2proxy.resource;

import com.example.oauth2proxy.config.OAuthConfig;
import com.example.oauth2proxy.service.CookieService;
import io.quarkus.oidc.IdTokenCredential;
import io.quarkus.oidc.RefreshToken;

import io.quarkus.security.credential.TokenCredential;
import io.vertx.core.http.Cookie;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.NewCookie;
import jakarta.ws.rs.core.Response;
import org.jboss.resteasy.reactive.RestCookie;
import org.jboss.resteasy.reactive.RestResponse;

import java.net.URI;

@Path("/auth")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class AuthResource {

    @Inject
    TokenCredential idToken;

    @Inject
    RefreshToken refreshToken;

    @Inject
    CookieService cookieService;

    @Inject
    OAuthConfig config;

    @GET
    @Path("/callback")
    public RestResponse<Void> callback() {
        String token = idToken.getToken();
        NewCookie authCookie = cookieService.createAuthCookie(token);

        return RestResponse.ResponseBuilder.<Void>create(Response.Status.FOUND)
                .location(URI.create("/"))
                .cookie(authCookie)
                .build();
    }

    @GET
    @Path("/validate")
    public RestResponse<Void> validate(@RestCookie("AUTH_TOKEN") String token) {
        if (token == null || token.isEmpty()) {
            return RestResponse.status(Response.Status.UNAUTHORIZED);
        }

        if (cookieService.isValidToken(token)) {
            return RestResponse.ResponseBuilder.<Void>ok()
                    .header(config.jwt().headerName(), token)
                    .build();
        } else {
            return RestResponse.status(Response.Status.UNAUTHORIZED);
        }
    }

    @GET
    @Path("/logout")
    public RestResponse<Void> logout() {
        NewCookie logoutCookie = cookieService.createLogoutCookie();

        return RestResponse.ResponseBuilder.<Void>create(Response.Status.FOUND)
                .location(URI.create("/"))
                .cookie(logoutCookie)
                .build();
    }

    @GET
    @Path("/login")
    public RestResponse<Void> login() {
        // This endpoint will trigger the OIDC authentication flow
        // The actual redirect is handled by Quarkus OIDC extension
        return RestResponse.ok();
    }
}
package io.github.renegrob.oidc.resource;

import io.github.renegrob.oidc.config.FederationMode;
import io.github.renegrob.oidc.config.OAuthConfig;
import io.github.renegrob.oidc.service.idp.IdpConfigurationService;
import io.github.renegrob.oidc.service.internalissuer.InternalKeyInfo;
import io.smallrye.common.annotation.RunOnVirtualThread;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;

import java.io.IOException;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse.BodyHandlers;
import java.security.PublicKey;

import static java.net.http.HttpClient.newHttpClient;
import static java.net.http.HttpRequest.newBuilder;

@Path("auth/.well-known/jwks.json")
@SuppressWarnings("unused")
public class JwksResource {

    private final InternalKeyInfo internalKeyInfo;
    private final OAuthConfig config;
    private final IdpConfigurationService idpConfigurationService;

    @Inject
    public JwksResource(OAuthConfig config, InternalKeyInfo internalKeyInfo, IdpConfigurationService idpConfigurationService) {
        this.config = config;
        this.internalKeyInfo = internalKeyInfo;
        this.idpConfigurationService = idpConfigurationService;
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @RunOnVirtualThread
    public String getJwks() throws IOException, InterruptedException {
        if (config.federationMode() == FederationMode.PASS_THROUGH) {
            try (var client = newHttpClient()) {
                HttpRequest request = newBuilder(idpConfigurationService.jwksUri()).GET().build();
                return client.send(request, BodyHandlers.ofString()).body();
            }
        }

        try {
            // Retrieve the public key and key ID from the InternalIssuerService
            PublicKey publicKey = internalKeyInfo.publicKey();
            String keyId = internalKeyInfo.keyId();

            JsonWebKey jwk = JsonWebKey.Factory.newJwk(publicKey);
            jwk.setKeyId(keyId);

            JsonWebKeySet jwkSet = new JsonWebKeySet(jwk);
            return jwkSet.toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY);
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate JWKS", e);
        }
    }
}
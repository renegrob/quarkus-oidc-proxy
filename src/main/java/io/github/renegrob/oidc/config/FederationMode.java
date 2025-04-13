package io.github.renegrob.oidc.config;

public enum FederationMode {
    /**
     * Represents creating an internal ID token from the external ID token.
     */
    FEDERATE_FROM_ID_TOKEN,
    /**
     * Represents creating an internal ID token from the external access token.
     */
    FEDERATE_FROM_ACCESS_TOKEN,
    /**
     * Represents creating an internal ID token from the external access token and passing through the external ID token.
     */
    PASS_THROUGH
}

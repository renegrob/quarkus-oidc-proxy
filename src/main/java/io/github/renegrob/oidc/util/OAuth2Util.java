package io.github.renegrob.oidc.util;

import java.net.URI;
import java.net.URISyntaxException;

public final class OAuth2Util {
    public static URI uri(String uri) {
        if (uri == null || uri.isEmpty()) {
            return null;
        }
        try {
            return new URI(uri);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("Invalid URI: " + uri, e);
        }
    }
}

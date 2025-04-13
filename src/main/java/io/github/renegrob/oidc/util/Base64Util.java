package io.github.renegrob.oidc.util;

import java.util.Base64;

public final class Base64Util {
    public static String toBase64(byte[] data, boolean withoutPadding) {
        if (withoutPadding) {
            return Base64.getEncoder().withoutPadding().encodeToString(data);
        }
        return Base64.getEncoder().encodeToString(data);
    }

    public static byte[] base64ToBytes(String base64) {
        return Base64.getDecoder().decode(base64);
    }
}

package io.github.renegrob.oidc.service;

public interface SessionService {
    void store(String accessToken, String accessToken1);
}

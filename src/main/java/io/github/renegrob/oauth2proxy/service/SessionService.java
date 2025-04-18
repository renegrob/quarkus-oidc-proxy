package io.github.renegrob.oauth2proxy.service;

public interface SessionService {
    void store(String accessToken, String accessToken1);
}

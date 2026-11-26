package com.rmtekton.foodcore.infrastructure.security;

import com.rmtekton.foodcore.infrastructure.config.OpenApiConfig;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Component
@RequiredArgsConstructor
public class AuthCookieFactory {

    private final SecurityProperties securityProperties;

    public ResponseCookie createAccessTokenCookie(String accessToken) {
        if (accessToken == null || accessToken.isBlank()) {
            throw new IllegalArgumentException("O token de acesso é obrigatório para criação do cookie");
        }
        Long expirationHours = securityProperties.getJwt().getExpirationHours();
        if (expirationHours == null || expirationHours < 1) {
            throw new IllegalStateException("Tempo de expiração do JWT não configurado corretamente");
        }

        return ResponseCookie.from(OpenApiConfig.ACCESS_TOKEN_COOKIE_NAME, accessToken.trim())
                .httpOnly(true)
                .secure(securityProperties.getCookie().isSecure())
                .sameSite("Strict")
                .path("/")
                .maxAge(Duration.ofHours(expirationHours))
                .build();
    }

    public ResponseCookie createLogoutCookie() {
        return ResponseCookie.from(OpenApiConfig.ACCESS_TOKEN_COOKIE_NAME, "")
                .httpOnly(true)
                .secure(securityProperties.getCookie().isSecure())
                .sameSite("Strict")
                .path("/")
                .maxAge(Duration.ZERO)
                .build();
    }
}
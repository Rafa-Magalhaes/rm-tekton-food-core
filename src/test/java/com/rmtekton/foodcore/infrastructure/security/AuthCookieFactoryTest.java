package com.rmtekton.foodcore.infrastructure.security;

import com.rmtekton.foodcore.infrastructure.config.OpenApiConfig;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseCookie;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AuthCookieFactoryTest {

    @Test
    @DisplayName("Deve gerar Cookie HttpOnly, SameSite=Strict, Path=/ e respeitar flag secure parametrizada")
    void shouldCreateHardenedAccessTokenCookieRespectingSecureFlag() {
        SecurityProperties prodProps = new SecurityProperties();
        prodProps.getJwt().setExpirationHours(8L);
        prodProps.getCookie().setSecure(true);

        SecurityProperties devProps = new SecurityProperties();
        devProps.getJwt().setExpirationHours(2L);
        devProps.getCookie().setSecure(false);

        ResponseCookie prodCookie = new AuthCookieFactory(prodProps).createAccessTokenCookie("jwt.prod.token");
        ResponseCookie devCookie = new AuthCookieFactory(devProps).createAccessTokenCookie("jwt.dev.token");

        assertThat(prodCookie.getName()).isEqualTo(OpenApiConfig.ACCESS_TOKEN_COOKIE_NAME);
        assertThat(prodCookie.getValue()).isEqualTo("jwt.prod.token");
        assertThat(prodCookie.isHttpOnly()).isTrue();
        assertThat(prodCookie.isSecure()).isTrue();
        assertThat(prodCookie.getSameSite()).isEqualTo("Strict");
        assertThat(prodCookie.getPath()).isEqualTo("/");
        assertThat(prodCookie.getMaxAge()).isEqualTo(Duration.ofHours(8));

        assertThat(devCookie.isHttpOnly()).isTrue();
        assertThat(devCookie.isSecure()).isFalse();
        assertThat(devCookie.getMaxAge()).isEqualTo(Duration.ofHours(2));
    }

    @Test
    @DisplayName("Deve gerar Cookie de logout com Max-Age=0, valor vazio e flags de segurança preservadas")
    void shouldCreateLogoutCookieWithZeroMaxAge() {
        SecurityProperties props = new SecurityProperties();
        props.getCookie().setSecure(true);

        ResponseCookie logoutCookie = new AuthCookieFactory(props).createLogoutCookie();

        assertThat(logoutCookie.getName()).isEqualTo(OpenApiConfig.ACCESS_TOKEN_COOKIE_NAME);
        assertThat(logoutCookie.getValue()).isEmpty();
        assertThat(logoutCookie.isHttpOnly()).isTrue();
        assertThat(logoutCookie.isSecure()).isTrue();
        assertThat(logoutCookie.getSameSite()).isEqualTo("Strict");
        assertThat(logoutCookie.getPath()).isEqualTo("/");
        assertThat(logoutCookie.getMaxAge()).isEqualTo(Duration.ZERO);
    }

    @Test
    @DisplayName("Deve recusar geração de cookie quando token for nulo ou em branco")
    void shouldRejectNullOrBlankToken() {
        SecurityProperties props = new SecurityProperties();
        props.getJwt().setExpirationHours(8L);
        AuthCookieFactory factory = new AuthCookieFactory(props);

        assertThatThrownBy(() -> factory.createAccessTokenCookie(null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> factory.createAccessTokenCookie("   "))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
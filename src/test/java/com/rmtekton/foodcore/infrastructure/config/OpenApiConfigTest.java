package com.rmtekton.foodcore.infrastructure.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class OpenApiConfigTest {

    @Test
    @DisplayName("Deve configurar esquema de segurança do OpenAPI exclusivamente via Cookie HttpOnly")
    void shouldConfigureCookieAuthSecurityScheme() {
        OpenApiConfig config = new OpenApiConfig();

        OpenAPI openAPI = config.customOpenAPI();

        assertThat(openAPI.getInfo()).isNotNull();
        assertThat(openAPI.getInfo().getTitle()).isEqualTo("RM.Tekton — Food Core Engine");
        assertThat(openAPI.getInfo().getVersion()).isEqualTo("v1");
        assertThat(openAPI.getInfo().getDescription()).contains("Motor transacional multi-loja");

        SecurityScheme scheme = openAPI.getComponents()
                .getSecuritySchemes()
                .get(OpenApiConfig.COOKIE_AUTH_SCHEME);

        assertThat(scheme).isNotNull();
        assertThat(scheme.getType()).isEqualTo(SecurityScheme.Type.APIKEY);
        assertThat(scheme.getIn()).isEqualTo(SecurityScheme.In.COOKIE);
        assertThat(scheme.getName()).isEqualTo(OpenApiConfig.ACCESS_TOKEN_COOKIE_NAME);
        assertThat(scheme.getDescription()).contains("Cookie HttpOnly");
    }
}
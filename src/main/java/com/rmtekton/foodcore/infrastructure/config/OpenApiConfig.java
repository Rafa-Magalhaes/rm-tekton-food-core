package com.rmtekton.foodcore.infrastructure.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

    public static final String COOKIE_AUTH_SCHEME = "cookieAuth";
    public static final String ACCESS_TOKEN_COOKIE_NAME = "access_token";

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("RM.Tekton — Food Core Engine")
                        .version("v1")
                        .description("Motor transacional multi-loja para operações de Food Service: " +
                                "gestão de centros de estoque compartilhados, ingestão idempotente " +
                                "de pedidos, conciliação financeira passiva e geofencing plugável.")
                        .contact(new Contact()
                                .name("RM.Tekton")
                                .url("https://github.com/Rafa-Magalhaes/rm-tekton-food-core")))
                .addSecurityItem(new SecurityRequirement().addList(COOKIE_AUTH_SCHEME))
                .components(new Components()
                        .addSecuritySchemes(COOKIE_AUTH_SCHEME, new SecurityScheme()
                                .name(ACCESS_TOKEN_COOKIE_NAME)
                                .type(SecurityScheme.Type.APIKEY)
                                .in(SecurityScheme.In.COOKIE)
                                .description("Token JWT entregue exclusivamente via Cookie HttpOnly após autenticação")));
    }
}
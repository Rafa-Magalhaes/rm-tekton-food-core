package com.rmtekton.foodcore.infrastructure.security;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Getter
@Setter
@Validated
@ConfigurationProperties(prefix = "app.security")
public class SecurityProperties {

    @Valid
    @NotNull
    private Jwt jwt = new Jwt();

    @NotBlank(message = "A variável de ambiente SECURITY_PEPPER é obrigatória")
    @Size(min = 32, message = "A variável SECURITY_PEPPER deve conter no mínimo 32 caracteres")
    private String pepper;

    @Valid
    @NotNull
    private Cookie cookie = new Cookie();

    @Valid
    @NotNull
    private Cors cors = new Cors();

    @Getter
    @Setter
    public static class Jwt {

        @NotBlank(message = "A variável de ambiente JWT_SECRET é obrigatória")
        @Size(min = 32, message = "A variável JWT_SECRET deve conter no mínimo 32 caracteres")
        private String secret;

        @NotNull(message = "A variável de ambiente JWT_EXPIRATION_HOURS é obrigatória")
        @Min(value = 1, message = "JWT_EXPIRATION_HOURS deve ser de no mínimo 1 hora")
        @Max(value = 720, message = "JWT_EXPIRATION_HOURS não pode exceder 720 horas")
        private Long expirationHours;
    }

    @Getter
    @Setter
    public static class Cookie {

        private boolean secure = true;
    }

    @Getter
    @Setter
    public static class Cors {

        private java.util.List<String> allowedOrigins = java.util.List.of(
                "http://localhost:3000",
                "http://localhost:5173",
                "http://localhost:8086"
        );
    }
}
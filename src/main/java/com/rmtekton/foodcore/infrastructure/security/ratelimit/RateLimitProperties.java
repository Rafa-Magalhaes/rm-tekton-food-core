package com.rmtekton.foodcore.infrastructure.security.ratelimit;

import jakarta.validation.constraints.Min;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Getter
@Setter
@Validated
@ConfigurationProperties(prefix = "app.rate-limit")
public class RateLimitProperties {

    private boolean enabled = true;
    private boolean trustProxyHeaders = false;

    @Min(value = 1, message = "O limite de requisições de autenticação deve ser no mínimo 1 por minuto")
    private long authRequestsPerMinute = 5;

    @Min(value = 1, message = "O limite de requisições de escrita deve ser no mínimo 1 por minuto")
    private long writeRequestsPerMinute = 30;

    @Min(value = 1, message = "O limite de requisições de leitura deve ser no mínimo 1 por minuto")
    private long readRequestsPerMinute = 100;
}
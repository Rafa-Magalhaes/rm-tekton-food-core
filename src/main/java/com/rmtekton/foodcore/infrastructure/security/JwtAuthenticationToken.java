package com.rmtekton.foodcore.infrastructure.security;

import lombok.Getter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.UUID;

@Getter
public class JwtAuthenticationToken extends AbstractAuthenticationToken {

    private final UUID userId;
    private final String email;

    public JwtAuthenticationToken(
            UUID userId,
            String email,
            Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        if (userId == null) {
            throw new IllegalArgumentException("O userId é obrigatório para autenticação JWT");
        }
        if (email == null || email.isBlank()) {
            throw new IllegalArgumentException("O e-mail é obrigatório para autenticação JWT");
        }
        this.userId = userId;
        this.email = email;
        setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return this.userId;
    }
}
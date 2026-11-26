package com.rmtekton.foodcore.infrastructure.security;

import lombok.Builder;
import lombok.Getter;

import java.util.List;
import java.util.UUID;

@Getter
@Builder
public class JwtUserClaims {

    private final UUID userId;
    private final String email;
    private final List<String> roles;
}
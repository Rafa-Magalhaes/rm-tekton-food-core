package com.rmtekton.foodcore.domain.auth;

import com.rmtekton.foodcore.domain.user.User;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class AuthenticatedSession {

    private final User user;
    private final String accessToken;
}
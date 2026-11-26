package com.rmtekton.foodcore.api.auth.dto;

import com.rmtekton.foodcore.api.user.dto.UserResponseDTO;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class AuthSessionResponseDTO {

    private final String message;
    private final UserResponseDTO user;
}
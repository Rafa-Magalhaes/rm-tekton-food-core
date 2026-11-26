package com.rmtekton.foodcore.api.auth.dto;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class LogoutResponseDTO {

    private final String message;
}
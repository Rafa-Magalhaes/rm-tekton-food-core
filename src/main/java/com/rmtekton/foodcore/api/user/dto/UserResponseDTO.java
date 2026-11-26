package com.rmtekton.foodcore.api.user.dto;

import com.rmtekton.foodcore.domain.user.UserRole;
import lombok.Builder;
import lombok.Getter;

import java.time.OffsetDateTime;
import java.util.UUID;

@Getter
@Builder
public class UserResponseDTO {

    private final UUID id;
    private final String name;
    private final String email;
    private final UserRole role;
    private final OffsetDateTime createdAt;
}
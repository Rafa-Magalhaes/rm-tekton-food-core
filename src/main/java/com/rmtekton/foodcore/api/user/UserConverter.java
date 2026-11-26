package com.rmtekton.foodcore.api.user;

import com.rmtekton.foodcore.api.user.dto.UserResponseDTO;
import com.rmtekton.foodcore.domain.user.User;
import org.springframework.stereotype.Component;

@Component
public class UserConverter {

    public UserResponseDTO toResponse(User user) {
        if (user == null) {
            throw new IllegalArgumentException("O usuário não pode ser nulo para conversão");
        }
        return UserResponseDTO.builder()
                .id(user.getId())
                .name(user.getName())
                .email(user.getEmail())
                .role(user.getRole())
                .createdAt(user.getCreatedAt())
                .build();
    }
}
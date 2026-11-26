package com.rmtekton.foodcore.api.user.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class UserRegistrationRequestDTO {

    @NotBlank(message = "O nome é obrigatório")
    @Size(min = 2, max = 120, message = "O nome deve ter entre 2 e 120 caracteres")
    @Pattern(regexp = "^[^<>]*$", message = "Caracteres inválidos detectados")
    private String name;

    @NotBlank(message = "O e-mail é obrigatório")
    @Email(message = "Informe um endereço de e-mail válido")
    @Size(max = 180, message = "O e-mail deve ter no máximo 180 caracteres")
    @Pattern(regexp = "^[^<>]*$", message = "Caracteres inválidos detectados")
    private String email;

    @NotBlank(message = "A senha é obrigatória")
    @Size(min = 8, max = 128, message = "A senha deve ter entre 8 e 128 caracteres")
    private String password;
}
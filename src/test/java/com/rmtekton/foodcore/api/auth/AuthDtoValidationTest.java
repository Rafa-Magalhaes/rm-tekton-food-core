package com.rmtekton.foodcore.api.auth;

import com.rmtekton.foodcore.api.auth.dto.LoginRequestDTO;
import com.rmtekton.foodcore.api.user.dto.UserRegistrationRequestDTO;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class AuthDtoValidationTest {

    private static ValidatorFactory validatorFactory;
    private static Validator validator;

    @BeforeAll
    static void setUpValidator() {
        validatorFactory = Validation.buildDefaultValidatorFactory();
        validator = validatorFactory.getValidator();
    }

    @AfterAll
    static void closeValidator() {
        validatorFactory.close();
    }

    @Test
    @DisplayName("Deve aceitar cadastro válido com acentuação e apóstrofo em nomes brasileiros")
    void shouldAcceptValidBrazilianNameAndEmail() {
        UserRegistrationRequestDTO dto = UserRegistrationRequestDTO.builder()
                .name("José D'Ávila Magalhães")
                .email("jose.rafael@rmtekton.com")
                .password("SenhaForte#2026")
                .build();

        Set<ConstraintViolation<UserRegistrationRequestDTO>> violations = validator.validate(dto);

        assertThat(violations).isEmpty();
    }

    @Test
    @DisplayName("Deve bloquear tentativa de injeção XSS com tags HTML no nome e e-mail")
    void shouldBlockXssTagsInRegistrationAndLoginDtos() {
        UserRegistrationRequestDTO xssRegistration = UserRegistrationRequestDTO.builder()
                .name("<script>alert('xss')</script>")
                .email("teste@rmtekton.com")
                .password("SenhaForte123")
                .build();

        LoginRequestDTO xssLogin = LoginRequestDTO.builder()
                .email("<img src=x>@rmtekton.com")
                .password("SenhaForte123")
                .build();

        assertThat(validator.validate(xssRegistration))
                .extracting(ConstraintViolation::getMessage)
                .contains("Caracteres inválidos detectados");

        assertThat(validator.validate(xssLogin))
                .extracting(ConstraintViolation::getMessage)
                .contains("Caracteres inválidos detectados");
    }
}
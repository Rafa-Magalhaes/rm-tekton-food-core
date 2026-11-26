package com.rmtekton.foodcore.domain.user;

import com.rmtekton.foodcore.domain.exception.ConflictException;
import com.rmtekton.foodcore.domain.exception.ResourceNotFoundException;
import com.rmtekton.foodcore.infrastructure.security.PasswordHashingService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordHashingService passwordHashingService;

    @InjectMocks
    private UserService userService;

    @Nested
    @DisplayName("Cenários Padrão do UserService")
    class StandardScenarios {

        @Test
        @DisplayName("Deve normalizar e-mail, higienizar nome, gerar hash Argon2id e cadastrar usuário ativo com ROLE_USER")
        void shouldRegisterUserWithNormalizedInputsAndArgon2Hash() {
            when(userRepository.existsByEmail("rafael@rmtekton.com")).thenReturn(false);
            when(passwordHashingService.encode("SenhaForte123")).thenReturn("$argon2id$hash-seguro");
            when(userRepository.saveAndFlush(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

            User saved = userService.register("  Rafael Magalhães  ", "  RAFAEL@RMTEKTON.COM  ", "SenhaForte123");

            ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
            verify(userRepository).saveAndFlush(userCaptor.capture());

            User persisted = userCaptor.getValue();
            assertThat(persisted.getName()).isEqualTo("Rafael Magalhães");
            assertThat(persisted.getEmail()).isEqualTo("rafael@rmtekton.com");
            assertThat(persisted.getPasswordHash()).isEqualTo("$argon2id$hash-seguro");
            assertThat(persisted.getRole()).isEqualTo(UserRole.USER);
            assertThat(persisted.isActive()).isTrue();
            assertThat(saved).isSameAs(persisted);
        }

        @Test
        @DisplayName("Deve retornar usuário ativo ao consultar por ID")
        void shouldFindActiveUserById() {
            UUID userId = UUID.randomUUID();
            User user = User.builder()
                    .id(userId)
                    .name("Rafael")
                    .email("rafael@rmtekton.com")
                    .passwordHash("hash")
                    .role(UserRole.USER)
                    .active(true)
                    .build();

            when(userRepository.findByIdAndActiveTrue(userId)).thenReturn(Optional.of(user));

            User result = userService.findActiveById(userId);

            assertThat(result).isSameAs(user);
        }

        @Test
        @DisplayName("Deve executar Soft Delete (active=false) e jamais chamar DELETE físico")
        void shouldDeactivateUserUsingSoftDeleteAndNeverPhysicalDelete() {
            UUID userId = UUID.randomUUID();
            User user = User.builder()
                    .id(userId)
                    .name("Rafael")
                    .email("rafael@rmtekton.com")
                    .passwordHash("hash")
                    .role(UserRole.USER)
                    .active(true)
                    .build();

            when(userRepository.findByIdAndActiveTrue(userId)).thenReturn(Optional.of(user));

            userService.deactivateAccount(userId);

            assertThat(user.isActive()).isFalse();
            verify(userRepository).save(user);
            verify(userRepository, never()).delete(any());
            verify(userRepository, never()).deleteById(any());
        }
    }

    @Nested
    @DisplayName("Cenários Extremos e Cisnes Negros do UserService")
    class BlackSwanScenarios {

        @Test
        @DisplayName("Deve lançar ConflictException sem gastar CPU de Argon2id quando e-mail já existir")
        void shouldThrowConflictWithoutHashingWhenEmailAlreadyExists() {
            when(userRepository.existsByEmail("duplicado@rmtekton.com")).thenReturn(true);

            assertThatThrownBy(() -> userService.register("Rafael", "DUPLICADO@RMTEKTON.COM", "SenhaForte123"))
                    .isInstanceOf(ConflictException.class)
                    .hasMessage("Já existe uma conta cadastrada com este e-mail");

            verify(passwordHashingService, never()).encode(anyString());
            verify(userRepository, never()).saveAndFlush(any());
        }

        @Test
        @DisplayName("Deve traduzir DataIntegrityViolationException de condição de corrida em ConflictException (409)")
        void shouldTranslateRaceConditionConstraintViolationIntoConflictException() {
            when(userRepository.existsByEmail("corrida@rmtekton.com")).thenReturn(false);
            when(passwordHashingService.encode("SenhaForte123")).thenReturn("$argon2id$hash");
            when(userRepository.saveAndFlush(any(User.class)))
                    .thenThrow(new DataIntegrityViolationException("duplicate key value violates unique constraint uk_users_email"));

            assertThatThrownBy(() -> userService.register("Rafael", "corrida@rmtekton.com", "SenhaForte123"))
                    .isInstanceOf(ConflictException.class)
                    .hasMessage("Já existe uma conta cadastrada com este e-mail");
        }

        @Test
        @DisplayName("Deve rejeitar nome, e-mail ou senha nulos/em branco antes de tocar no repositório")
        void shouldRejectNullOrBlankInputsBeforeTouchingRepository() {
            assertThatThrownBy(() -> userService.register("   ", "a@b.com", "Senha1234"))
                    .isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(() -> userService.register("Rafael", null, "Senha1234"))
                    .isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(() -> userService.register("Rafael", "a@b.com", "   "))
                    .isInstanceOf(IllegalArgumentException.class);

            verify(userRepository, never()).existsByEmail(anyString());
            verify(passwordHashingService, never()).encode(anyString());
        }

        @Test
        @DisplayName("Deve lançar ResourceNotFoundException para ID nulo ou conta já desativada")
        void shouldThrowResourceNotFoundForNullIdOrInactiveUser() {
            UUID inactiveId = UUID.randomUUID();
            when(userRepository.findByIdAndActiveTrue(inactiveId)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> userService.findActiveById(null))
                    .isInstanceOf(ResourceNotFoundException.class)
                    .hasMessage("Usuário não encontrado");

            assertThatThrownBy(() -> userService.deactivateAccount(inactiveId))
                    .isInstanceOf(ResourceNotFoundException.class)
                    .hasMessage("Usuário não encontrado");

            verify(userRepository, never()).save(any());
        }
    }
}
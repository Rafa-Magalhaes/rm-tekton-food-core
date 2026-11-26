package com.rmtekton.foodcore.domain.auth;

import com.rmtekton.foodcore.domain.exception.InvalidCredentialsException;
import com.rmtekton.foodcore.domain.user.User;
import com.rmtekton.foodcore.domain.user.UserRepository;
import com.rmtekton.foodcore.domain.user.UserRole;
import com.rmtekton.foodcore.infrastructure.security.JwtTokenService;
import com.rmtekton.foodcore.infrastructure.security.PasswordHashingService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

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
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordHashingService passwordHashingService;

    @Mock
    private JwtTokenService jwtTokenService;

    @InjectMocks
    private AuthService authService;

    @Nested
    @DisplayName("Cenários Padrão de Autenticação")
    class StandardScenarios {

        @Test
        @DisplayName("Deve autenticar usuário ativo normalizando o e-mail e emitir token JWT")
        void shouldAuthenticateActiveUserAndReturnSession() {
            User user = User.builder()
                    .id(UUID.randomUUID())
                    .name("Rafael")
                    .email("rafael@rmtekton.com")
                    .passwordHash("$argon2id$hash")
                    .role(UserRole.USER)
                    .active(true)
                    .build();

            when(userRepository.findByEmailAndActiveTrue("rafael@rmtekton.com")).thenReturn(Optional.of(user));
            when(passwordHashingService.matches("SenhaCorreta123", "$argon2id$hash")).thenReturn(true);
            when(jwtTokenService.generateToken(user)).thenReturn("jwt.assinado.valido");

            AuthenticatedSession session = authService.authenticate("  RAFAEL@RMTEKTON.COM ", "SenhaCorreta123");

            assertThat(session.getUser()).isSameAs(user);
            assertThat(session.getAccessToken()).isEqualTo("jwt.assinado.valido");
            verify(passwordHashingService, never()).performTimingAttackMitigation(anyString());
        }
    }

    @Nested
    @DisplayName("Cenários Extremos e Cisnes Negros (Anti-Timing Attack e Enumeração)")
    class BlackSwanScenarios {

        @Test
        @DisplayName("Deve executar hash fantasma (Timing Attack Mitigation) quando e-mail não existir ou estiver inativo")
        void shouldRunTimingAttackMitigationWhenUserNotFoundOrInactive() {
            when(userRepository.findByEmailAndActiveTrue("inexistente@rmtekton.com")).thenReturn(Optional.empty());

            assertThatThrownBy(() -> authService.authenticate("Inexistente@RMTEKTON.com", "QualquerSenha123"))
                    .isInstanceOf(InvalidCredentialsException.class)
                    .hasMessage("E-mail ou senha inválidos");

            verify(passwordHashingService).performTimingAttackMitigation("QualquerSenha123");
            verify(passwordHashingService, never()).matches(anyString(), anyString());
            verify(jwtTokenService, never()).generateToken(any());
        }

        @Test
        @DisplayName("Deve lançar exatamente a mesma mensagem genérica quando senha for incorreta")
        void shouldThrowSameGenericMessageWhenPasswordIsWrong() {
            User user = User.builder()
                    .id(UUID.randomUUID())
                    .name("Rafael")
                    .email("rafael@rmtekton.com")
                    .passwordHash("$argon2id$hash")
                    .role(UserRole.USER)
                    .active(true)
                    .build();

            when(userRepository.findByEmailAndActiveTrue("rafael@rmtekton.com")).thenReturn(Optional.of(user));
            when(passwordHashingService.matches("SenhaErrada", "$argon2id$hash")).thenReturn(false);

            assertThatThrownBy(() -> authService.authenticate("rafael@rmtekton.com", "SenhaErrada"))
                    .isInstanceOf(InvalidCredentialsException.class)
                    .hasMessage("E-mail ou senha inválidos");

            verify(jwtTokenService, never()).generateToken(any());
        }

        @Test
        @DisplayName("Deve executar mitigação de Timing Attack e recusar entradas nulas ou em branco")
        void shouldMitigateTimingAndRejectNullOrBlankCredentials() {
            assertThatThrownBy(() -> authService.authenticate(null, "Senha123"))
                    .isInstanceOf(InvalidCredentialsException.class)
                    .hasMessage("E-mail ou senha inválidos");

            assertThatThrownBy(() -> authService.authenticate("rafael@rmtekton.com", "   "))
                    .isInstanceOf(InvalidCredentialsException.class)
                    .hasMessage("E-mail ou senha inválidos");

            verify(passwordHashingService).performTimingAttackMitigation("Senha123");
            verify(passwordHashingService).performTimingAttackMitigation("   ");
            verify(userRepository, never()).findByEmailAndActiveTrue(anyString());
        }
    }
}
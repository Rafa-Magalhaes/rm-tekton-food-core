package com.rmtekton.foodcore.infrastructure.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PasswordHashingServiceTest {

    private static final String VALID_PEPPER = "ValidTestPepper32CharsMinimum2026";
    private static final String DIFFERENT_PEPPER = "AnotherDifferentPepper32Chars2026";

    private SecurityProperties securityProperties;
    private PasswordHashingService hashingService;

    @BeforeEach
    void setUp() {
        securityProperties = new SecurityProperties();
        securityProperties.setPepper(VALID_PEPPER);

        hashingService = new PasswordHashingService(securityProperties);
        hashingService.initializeDummyHash();
    }

    @Nested
    @DisplayName("Cenários Padrão de Hash Argon2id + Pepper")
    class StandardScenarios {

        @Test
        @DisplayName("Deve gerar hash Argon2id distinto do texto puro e validar corretamente a senha")
        void shouldEncodeWithArgon2idAndMatchValidPassword() {
            String rawPassword = "StrongPassword123";

            String encoded = hashingService.encode(rawPassword);

            assertThat(encoded)
                    .isNotBlank()
                    .doesNotContain(rawPassword)
                    .doesNotContain(VALID_PEPPER)
                    .startsWith("$argon2id$");
            assertThat(hashingService.matches(rawPassword, encoded)).isTrue();
            assertThat(hashingService.matches("WrongPassword123", encoded)).isFalse();
        }

        @Test
        @DisplayName("Deve gerar hashes diferentes para a mesma senha devido ao salt aleatório")
        void shouldGenerateDifferentHashesForSamePasswordDueToRandomSalt() {
            String hash1 = hashingService.encode("SamePassword2026");
            String hash2 = hashingService.encode("SamePassword2026");

            assertThat(hash1).isNotEqualTo(hash2);
            assertThat(hashingService.matches("SamePassword2026", hash1)).isTrue();
            assertThat(hashingService.matches("SamePassword2026", hash2)).isTrue();
        }
    }

    @Nested
    @DisplayName("Cenários Extremos e Cisnes Negros")
    class BlackSwanScenarios {

        @Test
        @DisplayName("Deve invalidar autenticação se o Pepper for alterado ou corrompido (ex: aspas no .env)")
        void shouldFailMatchWhenPepperChangesOrContainsQuotes() {
            String encodedWithOriginalPepper = hashingService.encode("SecretPass99");

            SecurityProperties alteredProps = new SecurityProperties();
            alteredProps.setPepper("\"" + VALID_PEPPER + "\"");
            PasswordHashingService quotedPepperService = new PasswordHashingService(alteredProps);

            SecurityProperties otherProps = new SecurityProperties();
            otherProps.setPepper(DIFFERENT_PEPPER);
            PasswordHashingService otherPepperService = new PasswordHashingService(otherProps);

            assertThat(quotedPepperService.matches("SecretPass99", encodedWithOriginalPepper)).isFalse();
            assertThat(otherPepperService.matches("SecretPass99", encodedWithOriginalPepper)).isFalse();
        }

        @Test
        @DisplayName("Deve recusar senhas nulas ou em branco na geração de hash")
        void shouldRejectNullOrBlankPasswordOnEncode() {
            assertThatThrownBy(() -> hashingService.encode(null))
                    .isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(() -> hashingService.encode("   "))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("Deve retornar false sem exceção quando senha ou hash forem nulos, em branco ou corrompidos")
        void shouldReturnFalseSafelyForNullBlankOrCorruptedHash() {
            String validHash = hashingService.encode("MyPass123");

            assertThat(hashingService.matches(null, validHash)).isFalse();
            assertThat(hashingService.matches("   ", validHash)).isFalse();
            assertThat(hashingService.matches("MyPass123", null)).isFalse();
            assertThat(hashingService.matches("MyPass123", "   ")).isFalse();
            assertThat(hashingService.matches("MyPass123", "not-a-valid-argon2-hash")).isFalse();
        }

        @Test
        @DisplayName("Deve diferenciar senhas muito longas (>72 bytes) sem truncamento silencioso como ocorre no BCrypt")
        void shouldHandleLongPasswordsWithout72ByteTruncation() {
            String prefix75Chars = "A".repeat(75);
            String passA = prefix75Chars + "1";
            String passB = prefix75Chars + "2";

            String encodedA = hashingService.encode(passA);

            assertThat(hashingService.matches(passA, encodedA)).isTrue();
            assertThat(hashingService.matches(passB, encodedA)).isFalse();
        }

        @Test
        @DisplayName("Deve suportar caracteres Unicode e emojis sem corromper verificação")
        void shouldSupportUnicodeAndEmojiPasswords() {
            String unicodePassword = "Pizzaria🍕SãoJoão#2026";
            String encoded = hashingService.encode(unicodePassword);

            assertThat(hashingService.matches(unicodePassword, encoded)).isTrue();
            assertThat(hashingService.matches("Pizzaria🍕SaoJoao#2026", encoded)).isFalse();
        }

        @Test
        @DisplayName("Deve executar mitigação de Timing Attack mesmo com entrada nula ou sem @PostConstruct prévio")
        void shouldExecuteTimingAttackMitigationSafelyUnderExtremeInputs() {
            PasswordHashingService freshServiceWithoutPostConstruct = new PasswordHashingService(securityProperties);

            assertThatCode(() -> hashingService.performTimingAttackMitigation("any-password"))
                    .doesNotThrowAnyException();
            assertThatCode(() -> hashingService.performTimingAttackMitigation(null))
                    .doesNotThrowAnyException();
            assertThatCode(() -> freshServiceWithoutPostConstruct.performTimingAttackMitigation("late-init"))
                    .doesNotThrowAnyException();
        }

        @Test
        @DisplayName("Deve falhar imediatamente se o Pepper não estiver configurado")
        void shouldFailFastWhenPepperIsMissing() {
            SecurityProperties brokenProps = new SecurityProperties();
            brokenProps.setPepper("   ");
            PasswordHashingService brokenService = new PasswordHashingService(brokenProps);

            assertThatThrownBy(() -> brokenService.encode("Password123"))
                    .isInstanceOf(IllegalStateException.class);
        }
    }
}
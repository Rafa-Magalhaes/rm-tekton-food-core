package com.rmtekton.foodcore.infrastructure.security;

import com.rmtekton.foodcore.domain.user.User;
import com.rmtekton.foodcore.domain.user.UserRole;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtTokenServiceTest {

    private static final String VALID_SECRET = "ValidJwtSecretKey32CharsMin2026Rm";
    private static final String OTHER_SECRET = "OtherJwtSecretKey32CharsMin2026Rm";
    private static final Instant FIXED_NOW = Instant.parse("2026-11-26T12:00:00Z");

    private SecurityProperties properties;
    private Clock fixedClock;
    private JwtTokenService jwtTokenService;
    private User sampleUser;

    @BeforeEach
    void setUp() {
        properties = buildProperties(VALID_SECRET, 8L);
        fixedClock = Clock.fixed(FIXED_NOW, ZoneOffset.UTC);
        jwtTokenService = new JwtTokenService(properties, fixedClock);
        jwtTokenService.initializeSigningKey();

        sampleUser = User.builder()
                .id(UUID.randomUUID())
                .name("Rafael Magalhães")
                .email("rafael@rmtekton.com")
                .passwordHash("$argon2id$v=19$m=16384,t=2,p=1$fake$hash")
                .role(UserRole.USER)
                .active(true)
                .build();
    }

    private SecurityProperties buildProperties(String secret, Long expirationHours) {
        SecurityProperties props = new SecurityProperties();
        props.setPepper("ValidPepperForTest32CharsMin2026A");
        props.getJwt().setSecret(secret);
        props.getJwt().setExpirationHours(expirationHours);
        return props;
    }

    @Nested
    @DisplayName("Cenários Padrão de Geração e Validação JWT")
    class StandardScenarios {

        @Test
        @DisplayName("Deve gerar JWT válido contendo userId, email e ROLE_USER e extrair claims corretamente")
        void shouldGenerateAndValidateJwtWithExpectedClaims() {
            String token = jwtTokenService.generateToken(sampleUser);

            Optional<JwtUserClaims> result = jwtTokenService.validateAndExtractClaims(token);

            assertThat(result).isPresent();
            assertThat(result.get().getUserId()).isEqualTo(sampleUser.getId());
            assertThat(result.get().getEmail()).isEqualTo("rafael@rmtekton.com");
            assertThat(result.get().getRoles()).containsExactly("ROLE_USER");
        }

        @Test
        @DisplayName("Deve incluir ROLE_ADMIN para usuário administrador")
        void shouldEncodeAdminRoleCorrectly() {
            User admin = User.builder()
                    .id(UUID.randomUUID())
                    .name("Admin")
                    .email("admin@rmtekton.com")
                    .passwordHash("hash")
                    .role(UserRole.ADMIN)
                    .build();

            String token = jwtTokenService.generateToken(admin);
            Optional<JwtUserClaims> result = jwtTokenService.validateAndExtractClaims(token);

            assertThat(result).isPresent();
            assertThat(result.get().getRoles()).containsExactly("ROLE_ADMIN");
        }
    }

    @Nested
    @DisplayName("Cenários Extremos e Cisnes Negros de Segurança JWT")
    class BlackSwanScenarios {

        @Test
        @DisplayName("Deve rejeitar token expirado avançando o relógio 1 segundo após o limite de expiração")
        void shouldRejectExpiredTokenDeterministically() {
            String token = jwtTokenService.generateToken(sampleUser);

            Clock futureClock = Clock.fixed(FIXED_NOW.plus(Duration.ofHours(8)).plusSeconds(1), ZoneOffset.UTC);
            JwtTokenService futureValidator = new JwtTokenService(properties, futureClock);
            futureValidator.initializeSigningKey();

            assertThat(futureValidator.validateAndExtractClaims(token)).isEmpty();
        }

        @Test
        @DisplayName("Deve rejeitar token assinado com chave secreta diferente (prevenção de Account Takeover)")
        void shouldRejectTokenSignedWithDifferentSecret() {
            JwtTokenService attackerService = new JwtTokenService(buildProperties(OTHER_SECRET, 8L), fixedClock);
            attackerService.initializeSigningKey();
            String forgedToken = attackerService.generateToken(sampleUser);

            assertThat(jwtTokenService.validateAndExtractClaims(forgedToken)).isEmpty();
        }

        @Test
        @DisplayName("Deve rejeitar token cujo payload foi adulterado (ex: tentativa de elevar para ROLE_ADMIN)")
        void shouldRejectTamperedPayloadToken() {
            String validToken = jwtTokenService.generateToken(sampleUser);
            String[] parts = validToken.split("\\.");

            String decodedPayload = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
            String tamperedPayload = decodedPayload.replace("ROLE_USER", "ROLE_ADMIN");
            String reencodedPayload = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(tamperedPayload.getBytes(StandardCharsets.UTF_8));
            String tamperedToken = parts[0] + "." + reencodedPayload + "." + parts[2];

            assertThat(jwtTokenService.validateAndExtractClaims(tamperedToken)).isEmpty();
        }

        @Test
        @DisplayName("Deve rejeitar ataque alg=none (token sem assinatura)")
        void shouldRejectAlgNoneAttackToken() {
            String header = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString("{\"alg\":\"none\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
            String payload = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(("{\"iss\":\"rm-tekton-food-core\",\"sub\":\"" + sampleUser.getId()
                            + "\",\"email\":\"a@b.com\",\"roles\":[\"ROLE_ADMIN\"]}").getBytes(StandardCharsets.UTF_8));
            String unsignedToken = header + "." + payload + ".";

            assertThat(jwtTokenService.validateAndExtractClaims(unsignedToken)).isEmpty();
        }

        @Test
        @DisplayName("Deve rejeitar token válido porém emitido por outro issuer")
        void shouldRejectTokenWithWrongIssuer() {
            String wrongIssuerToken = Jwts.builder()
                    .issuer("outro-sistema-externo")
                    .subject(sampleUser.getId().toString())
                    .claim(JwtTokenService.CLAIM_EMAIL, sampleUser.getEmail())
                    .claim(JwtTokenService.CLAIM_ROLES, List.of("ROLE_USER"))
                    .issuedAt(Date.from(FIXED_NOW))
                    .expiration(Date.from(FIXED_NOW.plus(Duration.ofHours(1))))
                    .signWith(Keys.hmacShaKeyFor(VALID_SECRET.getBytes(StandardCharsets.UTF_8)), Jwts.SIG.HS256)
                    .compact();

            assertThat(jwtTokenService.validateAndExtractClaims(wrongIssuerToken)).isEmpty();
        }

        @Test
        @DisplayName("Deve rejeitar token com subject não-UUID ou sem roles válidas")
        void shouldRejectTokenWithInvalidSubjectOrEmptyRoles() {
            var key = Keys.hmacShaKeyFor(VALID_SECRET.getBytes(StandardCharsets.UTF_8));

            String badSubjectToken = Jwts.builder()
                    .issuer(JwtTokenService.TOKEN_ISSUER)
                    .subject("not-a-uuid")
                    .claim(JwtTokenService.CLAIM_EMAIL, sampleUser.getEmail())
                    .claim(JwtTokenService.CLAIM_ROLES, List.of("ROLE_USER"))
                    .issuedAt(Date.from(FIXED_NOW))
                    .expiration(Date.from(FIXED_NOW.plus(Duration.ofHours(1))))
                    .signWith(key, Jwts.SIG.HS256)
                    .compact();

            String blankRolesToken = Jwts.builder()
                    .issuer(JwtTokenService.TOKEN_ISSUER)
                    .subject(sampleUser.getId().toString())
                    .claim(JwtTokenService.CLAIM_EMAIL, sampleUser.getEmail())
                    .claim(JwtTokenService.CLAIM_ROLES, List.of("   ", ""))
                    .issuedAt(Date.from(FIXED_NOW))
                    .expiration(Date.from(FIXED_NOW.plus(Duration.ofHours(1))))
                    .signWith(key, Jwts.SIG.HS256)
                    .compact();

            assertThat(jwtTokenService.validateAndExtractClaims(badSubjectToken)).isEmpty();
            assertThat(jwtTokenService.validateAndExtractClaims(blankRolesToken)).isEmpty();
        }

        @Test
        @DisplayName("Deve retornar vazio sem lançar exceção para tokens nulos, em branco ou lixo aleatório")
        void shouldReturnEmptyForNullBlankOrGarbageTokens() {
            assertThat(jwtTokenService.validateAndExtractClaims(null)).isEmpty();
            assertThat(jwtTokenService.validateAndExtractClaims("   ")).isEmpty();
            assertThat(jwtTokenService.validateAndExtractClaims("lixo.sem.sentido")).isEmpty();
            assertThat(jwtTokenService.validateAndExtractClaims("..")).isEmpty();
        }

        @Test
        @DisplayName("Deve recusar inicialização com chave secreta menor que 32 bytes e geração com usuário incompleto")
        void shouldFailFastOnWeakSecretAndIncompleteUser() {
            JwtTokenService weakService = new JwtTokenService(buildProperties("chave-curta-demais", 8L), fixedClock);
            assertThatThrownBy(weakService::initializeSigningKey)
                    .isInstanceOf(IllegalStateException.class);

            User incompleteUser = User.builder().email("sem-id@rmtekton.com").build();
            assertThatThrownBy(() -> jwtTokenService.generateToken(null))
                    .isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(() -> jwtTokenService.generateToken(incompleteUser))
                    .isInstanceOf(IllegalArgumentException.class);
        }
    }
}
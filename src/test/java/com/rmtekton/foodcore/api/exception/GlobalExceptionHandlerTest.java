package com.rmtekton.foodcore.api.exception;

import com.rmtekton.foodcore.domain.exception.BusinessRuleException;
import com.rmtekton.foodcore.domain.exception.ConflictException;
import com.rmtekton.foodcore.domain.exception.ResourceNotFoundException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.mock.http.MockHttpInputMessage;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.validation.FieldError;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.MethodArgumentNotValidException;

import java.lang.reflect.Method;
import java.time.OffsetDateTime;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;

class GlobalExceptionHandlerTest {

    private GlobalExceptionHandler handler;
    private MockHttpServletRequest request;
    private MethodParameter dummyMethodParameter;

    @BeforeEach
    void setUp() throws NoSuchMethodException {
        handler = new GlobalExceptionHandler();
        request = new MockHttpServletRequest("POST", "/api/v1/stores");
        Method dummyMethod = DummyController.class.getDeclaredMethod("handle", String.class);
        dummyMethodParameter = new MethodParameter(dummyMethod, 0);
    }

    private static class DummyController {
        @SuppressWarnings("unused")
        void handle(String payload) {
        }
    }

    @Nested
    @DisplayName("Cenários Padrão de Domínio e HTTP")
    class StandardScenarios {

        @Test
        @DisplayName("Deve retornar 404 com mensagem higienizada quando ResourceNotFoundException for lançada")
        void shouldReturn404WhenResourceNotFound() {
            ResourceNotFoundException ex = new ResourceNotFoundException("  Loja não encontrada  ");

            ResponseEntity<ErrorResponseDTO> response = handler.handleResourceNotFound(ex, request);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody().getStatus()).isEqualTo(404);
            assertThat(response.getBody().getError()).isEqualTo("Recurso não encontrado");
            assertThat(response.getBody().getMessage()).isEqualTo("Loja não encontrada");
            assertThat(response.getBody().getPath()).isEqualTo("/api/v1/stores");
            assertThat(response.getBody().getFields()).isNull();
            assertThat(response.getBody().getTimestamp()).isBeforeOrEqualTo(OffsetDateTime.now());
        }

        @Test
        @DisplayName("Deve retornar 409 quando ConflictException for lançada")
        void shouldReturn409WhenConflictOccurs() {
            ConflictException ex = new ConflictException("E-mail já cadastrado");

            ResponseEntity<ErrorResponseDTO> response = handler.handleConflict(ex, request);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody().getStatus()).isEqualTo(409);
            assertThat(response.getBody().getError()).isEqualTo("Conflito de dados");
            assertThat(response.getBody().getMessage()).isEqualTo("E-mail já cadastrado");
            assertThat(response.getBody().getFields()).isNull();
        }

        @Test
        @DisplayName("Deve retornar 422 quando BusinessRuleException for lançada")
        void shouldReturn422WhenBusinessRuleIsViolated() {
            BusinessRuleException ex = new BusinessRuleException("O pedido já foi cancelado");

            ResponseEntity<ErrorResponseDTO> response = handler.handleBusinessRule(ex, request);

            assertThat(response.getStatusCode().value()).isEqualTo(422);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody().getStatus()).isEqualTo(422);
            assertThat(response.getBody().getError()).isEqualTo("Violação de regra de negócio");
            assertThat(response.getBody().getMessage()).isEqualTo("O pedido já foi cancelado");
        }

        @Test
        @DisplayName("Deve retornar 400 com lista de campos quando MethodArgumentNotValidException ocorrer")
        void shouldReturn400WithFieldErrors() {
            BeanPropertyBindingResult bindingResult = new BeanPropertyBindingResult(new Object(), "storeRequest");
            bindingResult.addError(new FieldError("storeRequest", "name", "O nome é obrigatório"));
            bindingResult.addError(new FieldError("storeRequest", "email", "Informe um e-mail válido"));
            MethodArgumentNotValidException ex = new MethodArgumentNotValidException(dummyMethodParameter, bindingResult);

            ResponseEntity<ErrorResponseDTO> response = handler.handleValidationErrors(ex, request);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody().getStatus()).isEqualTo(400);
            assertThat(response.getBody().getError()).isEqualTo("Erro de validação");
            assertThat(response.getBody().getMessage()).isEqualTo("Um ou mais campos informados são inválidos");
            assertThat(response.getBody().getFields()).hasSize(2);
            assertThat(response.getBody().getFields())
                    .extracting(FieldErrorDTO::getField, FieldErrorDTO::getMessage)
                    .containsExactly(
                            tuple("name", "O nome é obrigatório"),
                            tuple("email", "Informe um e-mail válido")
                    );
        }
    }

    @Nested
    @DisplayName("Cenários Extremos e Cisnes Negros")
    class BlackSwanScenarios {

        @Test
        @DisplayName("Deve aplicar mensagem padrão em português quando exceções vierem com mensagem nula ou em branco")
        void shouldFallbackWhenExceptionMessagesAreNullOrBlank() {
            ResponseEntity<ErrorResponseDTO> notFoundNull =
                    handler.handleResourceNotFound(new ResourceNotFoundException(null), request);
            ResponseEntity<ErrorResponseDTO> conflictBlank =
                    handler.handleConflict(new ConflictException("   "), request);
            ResponseEntity<ErrorResponseDTO> businessWhitespace =
                    handler.handleBusinessRule(new BusinessRuleException("\t\n"), request);

            assertThat(notFoundNull.getBody()).isNotNull();
            assertThat(notFoundNull.getBody().getMessage()).isEqualTo("O recurso solicitado não foi encontrado");
            assertThat(conflictBlank.getBody()).isNotNull();
            assertThat(conflictBlank.getBody().getMessage()).isEqualTo("Ocorreu um conflito de dados");
            assertThat(businessWhitespace.getBody()).isNotNull();
            assertThat(businessWhitespace.getBody().getMessage()).isEqualTo("Uma regra de negócio foi violada");
        }

        @Test
        @DisplayName("Deve preservar todas as violações quando o mesmo campo falhar em múltiplas validações simultaneamente")
        void shouldHandleDuplicateErrorsOnSameFieldWithoutCrashing() {
            BeanPropertyBindingResult bindingResult = new BeanPropertyBindingResult(new Object(), "userRequest");
            bindingResult.addError(new FieldError("userRequest", "email", "O e-mail é obrigatório"));
            bindingResult.addError(new FieldError("userRequest", "email", "Caracteres inválidos detectados"));
            bindingResult.addError(new FieldError("userRequest", "email", "Tamanho deve ser entre 5 e 100 caracteres"));
            MethodArgumentNotValidException ex = new MethodArgumentNotValidException(dummyMethodParameter, bindingResult);

            ResponseEntity<ErrorResponseDTO> response = handler.handleValidationErrors(ex, request);

            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody().getFields()).hasSize(3);
            assertThat(response.getBody().getFields())
                    .allSatisfy(item -> assertThat(item.getField()).isEqualTo("email"));
        }

        @Test
        @DisplayName("Deve capturar erros globais de classe (ObjectError) junto com erros de campo")
        void shouldCaptureGlobalObjectErrorsAlongsideFieldErrors() {
            BeanPropertyBindingResult bindingResult = new BeanPropertyBindingResult(new Object(), "orderRequest");
            bindingResult.addError(new FieldError("orderRequest", "quantity", "A quantidade deve ser positiva"));
            bindingResult.addError(new ObjectError("orderRequest", "Pizza meio a meio exige exatamente 2 sabores"));
            MethodArgumentNotValidException ex = new MethodArgumentNotValidException(dummyMethodParameter, bindingResult);

            ResponseEntity<ErrorResponseDTO> response = handler.handleValidationErrors(ex, request);

            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody().getFields()).hasSize(2);
            assertThat(response.getBody().getFields())
                    .extracting(FieldErrorDTO::getField, FieldErrorDTO::getMessage)
                    .containsExactly(
                            tuple("quantity", "A quantidade deve ser positiva"),
                            tuple("orderRequest", "Pizza meio a meio exige exatamente 2 sabores")
                    );
        }

        @Test
        @DisplayName("Deve tratar defaultMessage nulo e BindingResult vazio sem lançar exceção")
        void shouldHandleNullDefaultMessageAndEmptyBindingResult() {
            BeanPropertyBindingResult nullMsgBinding = new BeanPropertyBindingResult(new Object(), "dto");
            nullMsgBinding.addError(new FieldError("dto", "price", null, false, null, null, null));
            MethodArgumentNotValidException exNullMsg = new MethodArgumentNotValidException(dummyMethodParameter, nullMsgBinding);

            ResponseEntity<ErrorResponseDTO> nullMsgResponse = handler.handleValidationErrors(exNullMsg, request);
            assertThat(nullMsgResponse.getBody()).isNotNull();
            assertThat(nullMsgResponse.getBody().getFields()).hasSize(1);
            assertThat(nullMsgResponse.getBody().getFields().getFirst().getMessage()).isEqualTo("Valor inválido");

            BeanPropertyBindingResult emptyBinding = new BeanPropertyBindingResult(new Object(), "dto");
            MethodArgumentNotValidException exEmpty = new MethodArgumentNotValidException(dummyMethodParameter, emptyBinding);

            ResponseEntity<ErrorResponseDTO> emptyResponse = handler.handleValidationErrors(exEmpty, request);
            assertThat(emptyResponse.getBody()).isNotNull();
            assertThat(emptyResponse.getBody().getFields()).isNull();
        }

        @Test
        @DisplayName("Deve suportar rajada de 100 erros de validação simultâneos sem falhar")
        void shouldHandleHighVolumeValidationErrors() {
            BeanPropertyBindingResult bindingResult = new BeanPropertyBindingResult(new Object(), "bulkRequest");
            IntStream.range(0, 100).forEach(i ->
                    bindingResult.addError(new FieldError("bulkRequest", "item[" + i + "]", "Item inválido"))
            );
            MethodArgumentNotValidException ex = new MethodArgumentNotValidException(dummyMethodParameter, bindingResult);

            ResponseEntity<ErrorResponseDTO> response = handler.handleValidationErrors(ex, request);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody().getFields()).hasSize(100);
        }

        @Test
        @DisplayName("Deve ocultar nomes internos de classes e detalhes do Jackson em respostas 400 de JSON malformado")
        void shouldNotLeakInternalClassesOnMalformedJson() {
            RuntimeException rootCause = new RuntimeException(
                    "Cannot deserialize value of type `com.rmtekton.foodcore.domain.Order` from String \"abc\""
            );
            HttpMessageNotReadableException ex = new HttpMessageNotReadableException(
                    "JSON parse error: com.rmtekton.foodcore.domain.Order",
                    rootCause,
                    new MockHttpInputMessage(new byte[0])
            );

            ResponseEntity<ErrorResponseDTO> response = handler.handleMalformedJson(ex, request);

            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
            assertThat(response.getBody()).isNotNull();
            assertThat(response.getBody().getError()).isEqualTo("Requisição malformada");
            assertThat(response.getBody().getMessage())
                    .doesNotContain("com.rmtekton")
                    .doesNotContain("deserialize")
                    .doesNotContain("Order");
        }

        @Test
        @DisplayName("Deve sobreviver a NullPointerException sem mensagem e erro SQL aninhado sem vazar segredos")
        void shouldHandleNullPointerAndNestedSqlExceptionsSafely() {
            RuntimeException sqlRoot = new RuntimeException("ERROR: relation \"internal_users_secret\" does not exist");
            RuntimeException wrapped = new RuntimeException((String) null, sqlRoot);
            NullPointerException bareNpe = new NullPointerException();

            ResponseEntity<ErrorResponseDTO> wrappedResponse = handler.handleUnexpectedError(wrapped, request);
            ResponseEntity<ErrorResponseDTO> bareNpeResponse = handler.handleUnexpectedError(bareNpe, request);

            assertThat(wrappedResponse.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
            assertThat(wrappedResponse.getBody()).isNotNull();
            assertThat(wrappedResponse.getBody().getError()).isEqualTo("Erro interno do servidor");
            assertThat(wrappedResponse.getBody().getMessage())
                    .isEqualTo("Ocorreu um erro inesperado. Tente novamente mais tarde.")
                    .doesNotContain("internal_users_secret")
                    .doesNotContain("relation");

            assertThat(bareNpeResponse.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
            assertThat(bareNpeResponse.getBody()).isNotNull();
            assertThat(bareNpeResponse.getBody().getMessage()).isNotBlank();
        }

        @Test
        @DisplayName("Deve tratar request nulo, URI em branco e ataque CRLF na URL sem quebrar o handler")
        void shouldHandleNullRequestAndMaliciousCrlfUriSafely() {
            ResponseEntity<ErrorResponseDTO> nullRequestResponse =
                    handler.handleResourceNotFound(new ResourceNotFoundException("Ausente"), null);
            assertThat(nullRequestResponse.getBody()).isNotNull();
            assertThat(nullRequestResponse.getBody().getPath()).isEqualTo("N/A");

            MockHttpServletRequest blankUriRequest = new MockHttpServletRequest("GET", "");
            ResponseEntity<ErrorResponseDTO> blankUriResponse =
                    handler.handleConflict(new ConflictException("Duplicado"), blankUriRequest);
            assertThat(blankUriResponse.getBody()).isNotNull();
            assertThat(blankUriResponse.getBody().getPath()).isEqualTo("N/A");

            MockHttpServletRequest crlfRequest = new MockHttpServletRequest(
                    "GET", "/api/v1/orders\r\nFAKE_LOG_ENTRY: admin logged in"
            );
            ResponseEntity<ErrorResponseDTO> crlfResponse =
                    handler.handleUnexpectedError(new RuntimeException("falha"), crlfRequest);
            assertThat(crlfResponse.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
            assertThat(crlfResponse.getBody()).isNotNull();
        }
    }
}
package com.rmtekton.foodcore.api.exception;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class FieldErrorDTO {

    private final String field;
    private final String message;
}
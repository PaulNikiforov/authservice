package com.innowise.authservice.exception;

public non-sealed class InvalidTokenException extends TokenException {

    public InvalidTokenException(String message) {
        super(message);
    }
}

package com.innowise.authservice.exception;

public final class InvalidTokenException extends TokenException {

    public InvalidTokenException(String message) {
        super(message);
    }
}

package com.innowise.authservice.exception;

public non-sealed class TokenExpiredException extends TokenException {

    public TokenExpiredException(String message) {
        super(message);
    }
}

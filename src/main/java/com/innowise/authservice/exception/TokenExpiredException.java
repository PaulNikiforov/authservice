package com.innowise.authservice.exception;

public final class TokenExpiredException extends TokenException {

    public TokenExpiredException(String message) {
        super(message);
    }
}

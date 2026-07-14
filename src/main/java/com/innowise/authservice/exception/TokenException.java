package com.innowise.authservice.exception;

public sealed class TokenException extends RuntimeException
        permits InvalidTokenException, TokenExpiredException {

    TokenException(String message) {
        super(message);
    }
}

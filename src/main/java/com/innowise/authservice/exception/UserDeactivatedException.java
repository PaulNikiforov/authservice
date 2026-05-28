package com.innowise.authservice.exception;

public class UserDeactivatedException extends RuntimeException {

    public UserDeactivatedException(String message) {
        super(message);
    }
}

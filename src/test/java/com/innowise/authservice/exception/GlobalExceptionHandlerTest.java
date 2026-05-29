package com.innowise.authservice.exception;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.validation.FieldError;
import org.springframework.validation.ObjectError;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;

import static org.assertj.core.api.Assertions.assertThat;

class GlobalExceptionHandlerTest {

    private GlobalExceptionHandler handler;
    private HttpServletRequest request;

    @BeforeEach
    void setUp() {
        handler = new GlobalExceptionHandler();
        request = new MockHttpServletRequest("POST", "/auth/login");
    }

    @Test
    void handleInvalidCredentials_shouldReturn401() {
        ResponseEntity<ErrorResponse> response = handler.handleInvalidCredentials(
                new InvalidCredentialsException("Bad credentials"), request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getBody().status()).isEqualTo(401);
        assertThat(response.getBody().error()).isEqualTo("Unauthorized");
        assertThat(response.getBody().message()).isEqualTo("Bad credentials");
        assertThat(response.getBody().path()).isEqualTo("/auth/login");
        assertThat(response.getBody().timestamp()).isNotNull();
    }

    @Test
    void handleTokenException_expired_shouldReturn401() {
        ResponseEntity<ErrorResponse> response = handler.handleTokenException(
                new TokenExpiredException("Token has expired"), request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getBody().message()).isEqualTo("Token has expired");
    }

    @Test
    void handleTokenException_invalid_shouldReturn401() {
        ResponseEntity<ErrorResponse> response = handler.handleTokenException(
                new InvalidTokenException("Bad token"), request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getBody().message()).isEqualTo("Bad token");
    }

    @Test
    void handleValidation_shouldReturn400WithFieldDetails() {
        BeanPropertyBindingResult bindingResult = new BeanPropertyBindingResult(new Object(), "request");
        bindingResult.addError(new FieldError("request", "email", "must not be blank"));
        bindingResult.addError(new FieldError("request", "password", "size must be between 8 and 128"));
        MethodArgumentNotValidException ex = new MethodArgumentNotValidException(null, bindingResult);

        ResponseEntity<ErrorResponse> response = handler.handleValidation(ex, request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody().status()).isEqualTo(400);
        assertThat(response.getBody().message()).contains("email: must not be blank", "password: size must be between 8 and 128");
    }

    @Test
    void handleValidation_withGlobalObjectError_shouldIncludeItInMessage() {
        BeanPropertyBindingResult bindingResult = new BeanPropertyBindingResult(new Object(), "request");
        bindingResult.addError(new FieldError("request", "email", "must not be blank"));
        bindingResult.addError(new ObjectError("request", "passwords must match"));
        MethodArgumentNotValidException ex = new MethodArgumentNotValidException(null, bindingResult);

        ResponseEntity<ErrorResponse> response = handler.handleValidation(ex, request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody().message())
                .contains("email: must not be blank", "request: passwords must match");
    }

    @Test
    void handleMethodNotAllowed_shouldReturn405() {
        ResponseEntity<ErrorResponse> response = handler.handleMethodNotAllowed(
                new HttpRequestMethodNotSupportedException("GET"), request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.METHOD_NOT_ALLOWED);
        assertThat(response.getBody().status()).isEqualTo(405);
    }

    @Test
    void handleUnsupportedMediaType_shouldReturn415() {
        ResponseEntity<ErrorResponse> response = handler.handleUnsupportedMediaType(
                new HttpMediaTypeNotSupportedException("text/plain"), request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNSUPPORTED_MEDIA_TYPE);
        assertThat(response.getBody().status()).isEqualTo(415);
    }

    @Test
    void handleDataIntegrity_shouldReturn409() {
        ResponseEntity<ErrorResponse> response = handler.handleDataIntegrity(
                new DataIntegrityViolationException("duplicate key value violates unique constraint"), request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        assertThat(response.getBody().status()).isEqualTo(409);
        assertThat(response.getBody().message()).isEqualTo("Resource already exists");
    }

    @Test
    void handleUserDeactivated_shouldReturn403() {
        ResponseEntity<ErrorResponse> response = handler.handleUserDeactivated(
                new UserDeactivatedException("Account deactivated"), request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(response.getBody().status()).isEqualTo(403);
        assertThat(response.getBody().message()).isEqualTo("Account deactivated");
    }

    @Test
    void handleUserAlreadyExists_shouldReturn409() {
        ResponseEntity<ErrorResponse> response = handler.handleUserAlreadyExists(
                new UserAlreadyExistsException("Duplicate email"), request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        assertThat(response.getBody().status()).isEqualTo(409);
        assertThat(response.getBody().message()).isEqualTo("Duplicate email");
    }

    @Test
    void handleFallback_shouldReturn500() {
        ResponseEntity<ErrorResponse> response = handler.handleFallback(
                new RuntimeException("Something broke"), request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(response.getBody().status()).isEqualTo(500);
        assertThat(response.getBody().message()).isEqualTo("Unexpected error");
    }
}

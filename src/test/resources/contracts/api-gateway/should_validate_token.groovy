import org.springframework.cloud.contract.spec.Contract

// JwtAuthFilter in api-gateway reads userId (→ X-User-Id) and role (→ X-User-Role).
// BaseValidateContractTest mocks JwtService so any non-blank string is accepted as token.
Contract.make {
    description "api-gateway JwtAuthFilter validates token; auth-service must return userId + role"
    request {
        method POST()
        url '/api/v1/auth/validate'
        headers { contentType(applicationJson()) }
        body([accessToken: anyNonBlankString()])
    }
    response {
        status OK()
        headers { contentType(applicationJson()) }
        body([
            userId: anyPositiveInt(),
            role  : anyNonBlankString()
        ])
    }
}

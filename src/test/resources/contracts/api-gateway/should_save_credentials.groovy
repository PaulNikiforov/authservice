import org.springframework.cloud.contract.spec.Contract

Contract.make {
    description "api-gateway registers credentials after user creation; reads accessToken + refreshToken"
    request {
        method POST()
        url '/api/v1/auth/credentials'
        headers { contentType(applicationJson()) }
        body([
            userId  : anyPositiveInt(),
            email   : 'contract@gateway.com',
            password: anyNonBlankString()
        ])
    }
    response {
        status CREATED()
        headers { contentType(applicationJson()) }
        body([
            accessToken : anyNonBlankString(),
            refreshToken: anyNonBlankString()
        ])
    }
}

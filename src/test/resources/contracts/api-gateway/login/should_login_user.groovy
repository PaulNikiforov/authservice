import org.springframework.cloud.contract.spec.Contract

// Uses concrete values so BaseContractTest.setUp() can pre-create matching credentials.
Contract.make {
    description "api-gateway proxies login; auth-service must return accessToken, refreshToken, userId, role"
    request {
        method POST()
        url '/api/v1/auth/login'
        headers { contentType(applicationJson()) }
        body([
            email   : 'contract@gateway.com',
            password: 'ContractPass1!'
        ])
    }
    response {
        status OK()
        headers { contentType(applicationJson()) }
        body([
            accessToken : anyNonBlankString(),
            refreshToken: anyNonBlankString(),
            userId      : anyPositiveInt(),
            role        : anyNonBlankString()
        ])
    }
}

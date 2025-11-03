import AdvancedTokenManager from '../src/index';

const auditLogger = {
    warn: (message: string) => console.log('[warn]', message),
    error: (message: string) => console.log('[error]', message)
};

const manager = new AdvancedTokenManager('manager-secret-change-me', ['salt-1', 'salt-2'], 'sha256', true, false, {
    logger: auditLogger,
    jwtDefaultAlgorithms: ['HS512'],
    throwOnValidationFailure: true,
    jwtMaxPayloadSize: 128,
    jwtAllowedClaims: ['transaction', 'amount']
});

const jwt = manager.generateJwt(
    { transaction: 'txn-123', amount: 99.99 },
    { algorithm: 'HS512', expiresIn: 120 }
);

const verified = manager.validateJwt(jwt);

console.log('Manager JWT:', jwt);
console.log('Manager payload:', verified);

try {
    manager.validateToken('not-a-valid-token');
} catch (error) {
    console.log('Token validation rejected input:', (error as Error).message);
}

try {
    const disallowedJwt = manager.generateJwt({ transaction: 'txn-999', scope: 'admin' });
    manager.validateJwt(disallowedJwt);
} catch (error) {
    console.log('Claim whitelist rejected JWT:', (error as Error).message);
}

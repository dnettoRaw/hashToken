// Example usage: npx ts-node examples/with-claims.ts
// In your application replace '../src' with 'hash-token'.
import { signJwt, verifyJwt } from '../src';

const secret = 'claims-demo-secret';
const issuedAt = Math.floor(Date.now() / 1000);

const token = signJwt(
    {
        sessionId: 'abc-123',
    },
    secret,
    {
        issuedAt,
        expiresIn: 600,
        notBefore: 5,
        audience: ['mobile', 'web'],
        issuer: 'auth-service',
        subject: 'user-777',
    }
);

console.log('JWT with claims:', token);

const { payload } = verifyJwt(token, secret, {
    issuer: 'auth-service',
    audience: ['mobile'],
    subject: 'user-777',
    clockTolerance: 10,
});

console.log('Verified claims:', payload);

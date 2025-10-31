// Example usage: npx ts-node examples/sign-verify.ts
// In your application replace '../src' with 'hash-token'.
import { signJwt, verifyJwt } from '../src';

const secret = 'demo-secret-key-for-jwt';

const token = signJwt(
    {
        userId: '42',
        permissions: ['profile:read', 'profile:write'],
    },
    secret,
    {
        expiresIn: 300,
        issuedAt: Math.floor(Date.now() / 1000),
    }
);

console.log('Generated JWT:', token);

const verification = verifyJwt(token, secret);
console.log('Decoded payload:', verification.payload);

import { signJwt, verifyJwt } from '../src/index';

const secret = 'example-secret-change-me';

const token = signJwt(
    { id: 'user-42', role: 'reader' },
    { secret, algorithm: 'HS256', expiresIn: 60 }
);

const payload = verifyJwt(token, {
    secret,
    maxPayloadSize: 256, // reject unexpectedly large payloads
    allowedClaims: ['id', 'role'] // only accept custom claims we expect
});

console.log('Generated JWT:', token);
console.log('Decoded payload:', payload);

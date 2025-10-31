import { signJwt, verifyJwt } from 'hash-token';

const secret = 'claims-secret-change-me';

const token = signJwt(
    { featureFlag: 'beta-access' },
    {
        secret,
        issuer: 'api.my-app.local',
        subject: 'user-1001',
        audience: ['dashboard', 'mobile-app'],
        notBefore: 5,
        expiresIn: 3600
    }
);

const payload = verifyJwt(token, {
    secret,
    issuer: ['api.my-app.local'],
    subject: 'user-1001',
    audience: 'mobile-app',
    clockTolerance: 5
});

console.log('JWT with claims:', token);
console.log('Verified payload:', payload);

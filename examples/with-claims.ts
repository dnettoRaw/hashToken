import { signJwt, verifyJwt } from '../src/index';

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
    clockTolerance: 5,
    allowedClaims: ['featureFlag']
});

console.log('JWT with claims:', token);
console.log('Verified payload:', payload);

try {
    verifyJwt(token, {
        secret,
        allowedClaims: ['scope'] // "featureFlag" is not in the allow list, so this fails
    });
} catch (error) {
    console.log('Strict claim whitelist rejected token:', (error as Error).message);
}

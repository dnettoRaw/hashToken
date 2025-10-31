// Example usage: npx ts-node examples/manager-integration.ts
// In your application replace '../src' with 'hash-token'.
import AdvancedTokenManager from '../src';

const manager = new AdvancedTokenManager('manager-secret-key', ['salt-1', 'salt-2']);

const jwt = manager.generateJwt(
    {
        workspaceId: 'ws-42',
        plan: 'pro',
    },
    {
        expiresIn: 900,
        audience: 'dashboard',
        issuer: 'billing-service',
    }
);

console.log('Manager generated JWT:', jwt);

const verification = manager.validateJwt(jwt, {
    audience: 'dashboard',
    issuer: 'billing-service',
});

console.log('Manager verified payload:', verification.payload);

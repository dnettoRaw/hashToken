import AdvancedTokenManager from '../src/index';

const manager = new AdvancedTokenManager('manager-secret-change-me', ['salt-1', 'salt-2']);

const jwt = manager.generateJwt(
    { transaction: 'txn-123', amount: 99.99 },
    { algorithm: 'HS512', expiresIn: 120 }
);

const verified = manager.validateJwt(jwt, { algorithms: ['HS512'] });

console.log('Manager JWT:', jwt);
console.log('Manager payload:', verified);

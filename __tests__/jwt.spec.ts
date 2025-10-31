import * as crypto from 'crypto';
import AdvancedTokenManager from '../src/AdvancedTokenManager';
import { base64Url, signJwt, verifyJwt } from '../src/jwt';

describe('JWT native support', () => {
    const secret = 'super-secret-test-key-1234567890';
    const issuedAt = 1_700_000_000;

    const manualToken = (header: unknown, payload: unknown, algorithm: 'HS256' | 'HS512' = 'HS256') => {
        const encodedHeader = base64Url.encode(JSON.stringify(header));
        const encodedPayload = base64Url.encode(JSON.stringify(payload));
        const digest = algorithm === 'HS256' ? 'sha256' : 'sha512';
        const signature = base64Url.encode(crypto.createHmac(digest, secret).update(`${encodedHeader}.${encodedPayload}`).digest());
        return `${encodedHeader}.${encodedPayload}.${signature}`;
    };

    it('signs and verifies payloads with HS256 by default', () => {
        const token = signJwt({ role: 'admin' }, secret, { issuedAt });
        const result = verifyJwt(token, secret, { currentTimestamp: issuedAt });
        expect(result.header.alg).toBe('HS256');
        expect(result.payload.role).toBe('admin');
    });

    it('supports HS512 with expiration control', () => {
        const token = signJwt({ scope: ['read'] }, secret, {
            algorithm: 'HS512',
            issuedAt,
            expiresIn: 120,
        });
        const result = verifyJwt(token, secret, {
            currentTimestamp: issuedAt + 60,
            algorithms: ['HS256', 'HS512'],
        });
        expect(result.header.alg).toBe('HS512');
        expect(result.payload.scope).toEqual(['read']);
    });

    it('rejects invalid signing options', () => {
        expect(() => signJwt({ demo: true }, secret, { issuer: '' })).toThrow('issuer must be a non-empty string.');
        expect(() => signJwt({ demo: true }, secret, { audience: [] })).toThrow('Audience array must contain non-empty strings.');
        expect(() => signJwt({ demo: true }, secret, { expiresIn: 0 })).toThrow('expiresIn must be a positive number.');
        expect(() => signJwt({ iat: 'bad' } as unknown as Record<string, unknown>, secret)).toThrow('Claim "iat" must be a finite number.');
        expect(() => signJwt({ sub: '' }, secret)).toThrow('Claim "sub" must be a non-empty string.');
        expect(() => signJwt({ algo: 'test' }, secret, { header: { alg: 'HS512' } as Record<string, unknown> })).toThrow('JWT header cannot override the signing algorithm.');
    });

    it('rejects tampered signatures', () => {
        const token = signJwt({ feature: 'jwt' }, secret, { issuedAt });
        const corrupted = token.replace(/.$/, (char) => (char === 'a' ? 'b' : 'a'));
        expect(() => verifyJwt(corrupted, secret, { currentTimestamp: issuedAt })).toThrow('Invalid JWT signature.');
    });

    it('rejects invalid base64 segments', () => {
        const token = `${base64Url.encode(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))}.@@@.${base64Url.encode('sig')}`;
        expect(() => verifyJwt(token, secret)).toThrow('Invalid base64url input.');
    });

    it('enforces allowed algorithms list', () => {
        const token = signJwt({ feature: 'jwt' }, secret, { issuedAt, algorithm: 'HS256' });
        expect(() => verifyJwt(token, secret, { algorithms: ['HS512'], currentTimestamp: issuedAt })).toThrow('Algorithm HS256 is not allowed.');
    });

    it('rejects expired tokens', () => {
        const token = signJwt({ session: 'abc' }, secret, { issuedAt, expiresIn: 10 });
        expect(() => verifyJwt(token, secret, { currentTimestamp: issuedAt + 11 })).toThrow('JWT has expired.');
    });

    it('enforces not-before with optional clock tolerance', () => {
        const token = signJwt({ session: 'nbf' }, secret, { issuedAt, notBefore: 30 });
        expect(() => verifyJwt(token, secret, { currentTimestamp: issuedAt + 10 })).toThrow('JWT is not valid yet.');
        const tolerant = verifyJwt(token, secret, { currentTimestamp: issuedAt + 10, clockTolerance: 25 });
        expect(tolerant.payload.session).toBe('nbf');
        expect(() => verifyJwt(token, secret, { currentTimestamp: issuedAt, clockTolerance: -1 })).toThrow('clockTolerance must be a non-negative number.');
    });

    it('validates issuer, audience and subject claims', () => {
        const token = signJwt({ resource: 'file' }, secret, {
            issuedAt,
            issuer: 'auth-service',
            audience: ['mobile', 'web'],
            subject: 'user-123',
        });

        const verified = verifyJwt(token, secret, {
            currentTimestamp: issuedAt + 5,
            issuer: 'auth-service',
            audience: ['mobile'],
            subject: 'user-123',
        });

        expect(verified.payload.resource).toBe('file');

        const multiSubject = verifyJwt(token, secret, { currentTimestamp: issuedAt, subject: ['user-123', 'user-999'] });
        expect(multiSubject.payload.resource).toBe('file');

        expect(() => verifyJwt(token, secret, { currentTimestamp: issuedAt, issuer: 'api-gateway' })).toThrow('JWT issuer does not match the expected value.');
        expect(() => verifyJwt(token, secret, { currentTimestamp: issuedAt, audience: 'desktop' })).toThrow('JWT audience does not match the expected value.');
        expect(() => verifyJwt(token, secret, { currentTimestamp: issuedAt, subject: 'user-456' })).toThrow('JWT subject does not match the expected value.');
        expect(() => verifyJwt(token, secret, { currentTimestamp: issuedAt, subject: '' as unknown as string })).toThrow('subject must be a non-empty string.');
        expect(() => verifyJwt(token, secret, { currentTimestamp: issuedAt, issuer: '' as unknown as string })).toThrow('issuer must be a non-empty string.');
    });

    it('applies maxAge validation using the iat claim', () => {
        const token = signJwt({ session: 'timed' }, secret, { issuedAt, expiresIn: 120 });
        const success = verifyJwt(token, secret, { currentTimestamp: issuedAt + 30, maxAge: 60 });
        expect(success.payload.session).toBe('timed');
        expect(() => verifyJwt(token, secret, { currentTimestamp: issuedAt + 100, maxAge: 60 })).toThrow('JWT has exceeded the allowed maxAge.');
        const missingIat = manualToken({ alg: 'HS256', typ: 'JWT' }, { data: true });
        expect(() => verifyJwt(missingIat, secret, { maxAge: 10, currentTimestamp: issuedAt })).toThrow('JWT is missing required "iat" claim for maxAge validation.');
        expect(() => verifyJwt(token, secret, { currentTimestamp: issuedAt + 10, maxAge: 0 })).toThrow('maxAge must be a positive number.');
    });

    it('rejects tokens when alg none is provided', () => {
        const header = base64Url.encode(JSON.stringify({ alg: 'none', typ: 'JWT' }));
        const payload = base64Url.encode(JSON.stringify({ role: 'guest' }));
        const forged = `${header}.${payload}.${base64Url.encode('fake')}`;
        expect(() => verifyJwt(forged, secret)).toThrow('Unsecured JWTs (alg "none") are not allowed.');
    });

    it('rejects malformed tokens and payloads', () => {
        const incomplete = signJwt({ data: 'value' }, secret, { issuedAt }).split('.').slice(0, 2).join('.');
        expect(() => verifyJwt(incomplete, secret)).toThrow('JWT must consist of three parts separated by dots.');

        const malformed = manualToken({ alg: 'HS256', typ: 'JWT' }, [1, 2, 3]);
        expect(() => verifyJwt(malformed, secret)).toThrow('Invalid JWT payload.');

        const badHeader = manualToken([], [1, 2, 3]);
        expect(() => verifyJwt(badHeader, secret)).toThrow('Invalid JWT header.');

        const badClaimsPayload = manualToken({ alg: 'HS256', typ: 'JWT' }, { nbf: 'later' });
        expect(() => verifyJwt(badClaimsPayload, secret)).toThrow('JWT claim "nbf" must be a finite number.');
    });

    it('rejects invalid payload inputs during signing', () => {
        expect(() => signJwt('invalid' as unknown as Record<string, unknown>, secret)).toThrow('JWT payload must be a plain object.');
    });

    it('integrates with AdvancedTokenManager', () => {
        const manager = new AdvancedTokenManager('integration-secret', ['salt-a', 'salt-b']);
        const token = manager.generateJwt({ feature: 'manager' }, { issuedAt });
        const result = manager.validateJwt(token, { currentTimestamp: issuedAt });
        expect(result.payload.feature).toBe('manager');
        expect(result.header.typ).toBe('JWT');
    });
});

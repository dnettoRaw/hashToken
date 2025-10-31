import { describe, expect, test } from '@jest/globals';
import * as crypto from 'crypto';
import AdvancedTokenManager from '../src/AdvancedTokenManager';
import { signJwt, verifyJwt, JwtAlgorithm } from '../src/jwt';

const SECRET = 'super-secret-test-secret-1234567890';

function toBase64Url(data: string | Buffer): string {
    const buffer = typeof data === 'string' ? Buffer.from(data, 'utf8') : Buffer.from(data);
    return buffer.toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function decodeBase64Url(segment: string): Buffer {
    const normalized = segment.replace(/-/g, '+').replace(/_/g, '/');
    const pad = (4 - (normalized.length % 4)) % 4;
    return Buffer.from(normalized + '='.repeat(pad), 'base64');
}

function createHmacToken(
    header: Record<string, unknown>,
    payload: unknown,
    secret: string = SECRET,
    algorithm: JwtAlgorithm = 'HS256'
): string {
    const headerSegment = toBase64Url(JSON.stringify(header));
    const payloadContent = typeof payload === 'string' || Buffer.isBuffer(payload)
        ? payload
        : JSON.stringify(payload);
    const payloadSegment = toBase64Url(payloadContent);
    const digestAlgorithm = algorithm === 'HS512' ? 'sha512' : 'sha256';
    const signature = toBase64Url(
        crypto.createHmac(digestAlgorithm, secret).update(`${headerSegment}.${payloadSegment}`).digest()
    );
    return `${headerSegment}.${payloadSegment}.${signature}`;
}

function makeJwt(payload: Record<string, unknown>, algorithm: JwtAlgorithm = 'HS256') {
    return signJwt(payload, { secret: SECRET, algorithm });
}

describe('JWT signing and verification', () => {
    test('signs and verifies payload using HS256', () => {
        const token = makeJwt({ user: 'alice' });
        const verified = verifyJwt<{ user: string; iat: number }>(token, { secret: SECRET });

        expect(verified.user).toBe('alice');
        expect(typeof verified.iat).toBe('number');
    });

    test('signs and verifies payload using HS512', () => {
        const token = makeJwt({ scope: 'admin' }, 'HS512');
        const verified = verifyJwt<{ scope: string }>(token, { secret: SECRET, algorithms: ['HS512'] });

        expect(verified.scope).toBe('admin');
    });

    test('rejects tokens signed with an unexpected algorithm', () => {
        const token = makeJwt({ flag: true }, 'HS256');
        expect(() => verifyJwt(token, { secret: SECRET, algorithms: ['HS512'] })).toThrow('Algorithm HS256 is not allowed.');
    });

    test('rejects tampered payloads', () => {
        const token = makeJwt({ id: 42 });
        const parts = token.split('.');
        const tamperedPayload = toBase64Url(JSON.stringify({ id: 43 }));
        const forgedToken = `${parts[0]}.${tamperedPayload}.${parts[2]}`;

        expect(() => verifyJwt(forgedToken, { secret: SECRET })).toThrow('Invalid JWT signature.');
    });

    test('rejects tokens with modified headers', () => {
        const token = makeJwt({ id: 123 });
        const parts = token.split('.');
        const header = JSON.parse(decodeBase64Url(parts[0]).toString('utf8'));
        header.alg = 'HS512';
        const forgedHeader = toBase64Url(JSON.stringify(header));
        const forgedToken = `${forgedHeader}.${parts[1]}.${parts[2]}`;

        expect(() => verifyJwt(forgedToken, { secret: SECRET })).toThrow('Invalid JWT signature.');
    });

    test('rejects alg none tokens', () => {
        const header = toBase64Url(JSON.stringify({ alg: 'none', typ: 'JWT' }));
        const payload = toBase64Url(JSON.stringify({ user: 'mallory' }));
        const fakeSignature = toBase64Url('ignored');
        const token = `${header}.${payload}.${fakeSignature}`;

        expect(() => verifyJwt(token, { secret: SECRET })).toThrow('Unsigned JWTs (alg "none") are not allowed.');
    });

    test('rejects invalid token structure', () => {
        expect(() => verifyJwt('invalid-token', { secret: SECRET })).toThrow('Invalid token structure.');
    });

    test('rejects invalid base64 segments', () => {
        const token = '@@@.def.ghi';
        expect(() => verifyJwt(token, { secret: SECRET })).toThrow('Invalid base64url encoding in header.');
    });

    test('rejects malformed base64 segments', () => {
        const token = 'ab.def.ghi';
        expect(() => verifyJwt(token, { secret: SECRET })).toThrow('Malformed base64url segment in header.');
    });

    test('expires tokens past exp claim', () => {
        const issuedAt = 1_000_000;
        const token = signJwt({ data: 'expiring' }, { secret: SECRET, issuedAt, expiresIn: 30, clockTimestamp: issuedAt });

        expect(() => verifyJwt(token, { secret: SECRET, clockTimestamp: issuedAt + 31 })).toThrow('JWT expired.');
        expect(() => verifyJwt(token, { secret: SECRET, clockTimestamp: issuedAt + 30 })).not.toThrow();
    });

    test('enforces not-before (nbf) with optional tolerance', () => {
        const token = signJwt({ feature: true }, { secret: SECRET, notBefore: 60, issuedAt: 0, clockTimestamp: 0 });

        expect(() => verifyJwt(token, { secret: SECRET, clockTimestamp: 10 })).toThrow('JWT not active yet.');
        expect(() => verifyJwt(token, { secret: SECRET, clockTimestamp: 10, clockTolerance: 60 })).not.toThrow();
    });

    test('validates issuer, audience, and subject claims', () => {
        const token = signJwt(
            { data: 'claims' },
            {
                secret: SECRET,
                issuer: 'issuer.example',
                audience: ['app-one', 'app-two'],
                subject: 'user-123'
            }
        );

        const payload = verifyJwt(token, {
            secret: SECRET,
            issuer: ['issuer.example'],
            audience: 'app-two',
            subject: 'user-123'
        });

        expect(payload.sub).toBe('user-123');
        expect(payload.iss).toBe('issuer.example');
    });

    test('rejects mismatching audiences', () => {
        const token = signJwt({ data: 'aud' }, { secret: SECRET, audience: 'service-a' });
        expect(() => verifyJwt(token, { secret: SECRET, audience: 'service-b' })).toThrow('JWT audience mismatch.');
    });

    test('rejects tokens missing required claims when expected', () => {
        const token = signJwt({ data: 'no-claims' }, { secret: SECRET });
        expect(() => verifyJwt(token, { secret: SECRET, audience: 'app' })).toThrow('JWT missing required audience claim.');
        expect(() => verifyJwt(token, { secret: SECRET, issuer: 'issuer' })).toThrow('JWT missing required issuer claim.');
        expect(() => verifyJwt(token, { secret: SECRET, subject: 'subject' })).toThrow('JWT missing required subject claim.');
    });

    test('rejects tokens issued in the future', () => {
        const token = signJwt({ data: 'future' }, { secret: SECRET, issuedAt: 1_000 });
        expect(() => verifyJwt(token, { secret: SECRET, clockTimestamp: 500 })).toThrow('JWT used before issued.');
    });

    test('enforces maxAge constraints', () => {
        const issuedAt = 10_000;
        const token = signJwt({ data: 'age' }, { secret: SECRET, issuedAt });

        expect(() => verifyJwt(token, { secret: SECRET, clockTimestamp: issuedAt + 100, maxAge: 90 })).toThrow('JWT exceeds maxAge.');
        expect(() => verifyJwt(token, { secret: SECRET, clockTimestamp: issuedAt + 80, maxAge: 90 })).not.toThrow();
    });

    test('rejects invalid claim types', () => {
        const header = toBase64Url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
        const payload = toBase64Url(JSON.stringify({ exp: 'soon' }));
        const signingInput = `${header}.${payload}`;
        const signature = toBase64Url(crypto.createHmac('sha256', SECRET).update(signingInput).digest());
        const token = `${signingInput}.${signature}`;

        expect(() => verifyJwt(token, { secret: SECRET })).toThrow('Claim "exp" must be a finite number.');
    });

    test('rejects verification with wrong secret', () => {
        const token = makeJwt({ session: 'abc' });
        expect(() => verifyJwt(token, { secret: 'wrong-secret' })).toThrow('Invalid JWT signature.');
    });

    test('integrates with AdvancedTokenManager', () => {
        const manager = new AdvancedTokenManager(SECRET, ['salt-a', 'salt-b']);
        const token = manager.generateJwt({ action: 'login' }, { algorithm: 'HS512' });
        const payload = manager.validateJwt<{ action: string; iat: number }>(token, { algorithms: ['HS512'] });

        expect(payload.action).toBe('login');
        expect(payload.iat).toBeDefined();
    });

    test('signJwt enforces payload format and options', () => {
        expect(() => signJwt('not-an-object' as unknown as Record<string, unknown>, { secret: SECRET })).toThrow('Payload must be a plain object.');
        expect(() => signJwt({}, { secret: SECRET, expiresIn: -10 })).toThrow('expiresIn must be a positive number of seconds.');
        expect(() => signJwt({}, { secret: SECRET, notBefore: Number.NaN })).toThrow('notBefore must be a number of seconds.');
        expect(() => signJwt({ iss: 'one' }, { secret: SECRET, issuer: 'two' })).toThrow('Claim "iss" already present with a different value.');
        expect(() => signJwt({}, { secret: SECRET, algorithm: 'HS256', header: { alg: 'HS512' } })).toThrow('Header algorithm mismatch.');
        expect(() => signJwt({}, { secret: '' })).toThrow('A non-empty secret is required to sign a JWT.');
        expect(() => signJwt({}, { secret: SECRET, algorithm: 'HS1024' as JwtAlgorithm })).toThrow('Unsupported signing algorithm: HS1024.');
        expect(() => signJwt({}, { secret: SECRET, header: { typ: 'JWS' } })).toThrow('Header type must be "JWT".');
        expect(() => signJwt({}, { secret: SECRET, clockTimestamp: Number.POSITIVE_INFINITY })).toThrow('clockTimestamp must be a finite number.');
        expect(() => signJwt({}, { secret: SECRET, audience: '' })).toThrow('Audience must be a non-empty string.');
        expect(() => signJwt({}, { secret: SECRET, audience: ['team', ''] as unknown as string[] })).toThrow('Audience must be a non-empty string.');
        expect(() => signJwt({ iat: 'now' } as unknown as Record<string, unknown>, { secret: SECRET })).toThrow('Claim "iat" must be a finite number.');
        expect(() => signJwt({ exp: 'soon' } as unknown as Record<string, unknown>, { secret: SECRET })).toThrow('Claim "exp" must be a finite number.');
        expect(() => signJwt({ nbf: 'later' } as unknown as Record<string, unknown>, { secret: SECRET })).toThrow('Claim "nbf" must be a finite number.');
        expect(() => signJwt({ sub: '' } as unknown as Record<string, unknown>, { secret: SECRET })).toThrow('Claim "sub" must be a non-empty string.');
    });

    test('signJwt supports pre-existing standard claims', () => {
        expect(() => signJwt({ aud: ['service-a', 'service-b'] } as unknown as Record<string, unknown>, { secret: SECRET })).not.toThrow();
        expect(() => signJwt({ aud: 'service-c' } as unknown as Record<string, unknown>, { secret: SECRET })).not.toThrow();
        expect(() => signJwt({ iss: 'issuer-a' } as unknown as Record<string, unknown>, { secret: SECRET })).not.toThrow();
        expect(() => signJwt({ sub: 'subject-a' } as unknown as Record<string, unknown>, { secret: SECRET })).not.toThrow();
    });

    test('verifyJwt validates option values', () => {
        const token = makeJwt({ check: true });
        expect(() => verifyJwt(token, { secret: SECRET, clockTolerance: -1 })).toThrow('clockTolerance must be a non-negative number.');
        const withIssuer = signJwt({ data: 'issuer' }, { secret: SECRET, issuer: 'issuer' });
        expect(() => verifyJwt(withIssuer, { secret: SECRET, issuer: [''] as unknown as string[] })).toThrow('Issuer values must be non-empty strings.');
        expect(() => verifyJwt(withIssuer, { secret: SECRET, issuer: '' as unknown as string })).toThrow('Issuer must be a non-empty string.');
        const withSubject = signJwt({ data: 'subject' }, { secret: SECRET, subject: 'subject' });
        expect(() => verifyJwt(withSubject, { secret: SECRET, subject: '' })).toThrow('Subject must be a non-empty string.');
        const withAudience = signJwt({ data: 'aud' }, { secret: SECRET, audience: 'valid' });
        expect(() => verifyJwt(withAudience, { secret: SECRET, audience: [] as unknown as string[] })).toThrow('Audience array must not be empty.');
        expect(() => verifyJwt(123 as unknown as string, { secret: SECRET })).toThrow('Token must be a non-empty string.');
        expect(() => verifyJwt('token', { secret: '' })).toThrow('A non-empty secret is required to verify a JWT.');
        expect(() => verifyJwt(token, { secret: SECRET, clockTimestamp: Number.NaN })).toThrow('clockTimestamp must be a finite number.');
        expect(() => verifyJwt(token, { secret: SECRET, maxAge: 0 })).toThrow('maxAge must be a positive number of seconds.');
    });

    test('rejects headers that fail JSON parsing', () => {
        const token = `${toBase64Url('invalid-json')}.${toBase64Url(JSON.stringify({ data: true }))}.${toBase64Url('sig')}`;
        expect(() => verifyJwt(token, { secret: SECRET })).toThrow('Invalid JWT header.');
    });

    test('rejects headers that are not JSON objects', () => {
        const token = `${toBase64Url('[]')}.${toBase64Url(JSON.stringify({ data: true }))}.${toBase64Url('sig')}`;
        expect(() => verifyJwt(token, { secret: SECRET })).toThrow('Invalid JWT header.');
    });

    test('rejects headers without required algorithm', () => {
        const token = createHmacToken({ typ: 'JWT' }, { data: true });
        expect(() => verifyJwt(token, { secret: SECRET })).toThrow('Missing JWT algorithm.');
    });

    test('rejects tokens with unsupported algorithms', () => {
        const token = createHmacToken({ typ: 'JWT', alg: 'RS256' }, { data: true });
        expect(() => verifyJwt(token, { secret: SECRET })).toThrow('Unsupported algorithm: RS256.');
    });

    test('rejects tokens with invalid type header', () => {
        const token = createHmacToken({ typ: 'JWS', alg: 'HS256' }, { data: true });
        expect(() => verifyJwt(token, { secret: SECRET })).toThrow('Invalid JWT type.');
    });

    test('rejects payloads that are not JSON objects', () => {
        const token = createHmacToken({ alg: 'HS256', typ: 'JWT' }, JSON.stringify('hello'));
        expect(() => verifyJwt(token, { secret: SECRET })).toThrow('Invalid JWT payload.');
    });

    test('rejects invalid payload JSON', () => {
        const token = createHmacToken({ alg: 'HS256', typ: 'JWT' }, '{');
        expect(() => verifyJwt(token, { secret: SECRET })).toThrow('Invalid JWT payload.');
    });

    test('rejects maxAge when iat is missing', () => {
        const token = createHmacToken({ alg: 'HS256', typ: 'JWT' }, { data: true });
        expect(() => verifyJwt(token, { secret: SECRET, maxAge: 10 })).toThrow('Cannot apply maxAge without an "iat" claim.');
    });

    test('allows optional claims when not enforced', () => {
        const token = signJwt({ aud: 'service', iss: 'issuer', sub: 'subject' }, { secret: SECRET });
        expect(() => verifyJwt(token, { secret: SECRET })).not.toThrow();
    });

    test('rejects issuer mismatch', () => {
        const token = signJwt({ iss: 'issuer-a' }, { secret: SECRET });
        expect(() => verifyJwt(token, { secret: SECRET, issuer: 'issuer-b' })).toThrow('JWT issuer mismatch.');
    });

    test('rejects issuer mismatch from list', () => {
        const token = signJwt({ iss: 'issuer-a' }, { secret: SECRET });
        expect(() => verifyJwt(token, { secret: SECRET, issuer: ['issuer-b', 'issuer-c'] })).toThrow('JWT issuer mismatch.');
    });

    test('rejects subject mismatch', () => {
        const token = signJwt({ sub: 'subject-a' }, { secret: SECRET });
        expect(() => verifyJwt(token, { secret: SECRET, subject: 'subject-b' })).toThrow('JWT subject mismatch.');
    });
});

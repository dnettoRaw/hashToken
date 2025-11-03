import * as crypto from 'crypto';

export type JwtAlgorithm = 'HS256' | 'HS512';

const HASH_ALGORITHMS: Record<JwtAlgorithm, string> = {
    HS256: 'sha256',
    HS512: 'sha512'
};

export interface JwtHeader {
    alg: JwtAlgorithm;
    typ: 'JWT';
    [key: string]: unknown;
}

export interface SignJwtOptions {
    secret: string;
    algorithm?: JwtAlgorithm;
    header?: Record<string, unknown>;
    expiresIn?: number;
    notBefore?: number;
    audience?: string | string[];
    issuer?: string;
    subject?: string;
    issuedAt?: number;
    clockTimestamp?: number;
}

export interface VerifyJwtOptions {
    secret: string;
    algorithms?: JwtAlgorithm[];
    clockTolerance?: number;
    audience?: string | string[];
    issuer?: string | string[];
    subject?: string;
    maxAge?: number;
    clockTimestamp?: number;
    maxPayloadSize?: number;
    allowedClaims?: string[];
}

interface JwtPayload extends Record<string, unknown> {
    exp?: number;
    nbf?: number;
    iat?: number;
    iss?: string;
    aud?: string | string[];
    sub?: string;
}

const BASE64URL_REGEXP = /^[A-Za-z0-9_-]*$/;
const STANDARD_CLAIMS = new Set(['iss', 'sub', 'aud', 'exp', 'nbf', 'iat']);

function isPlainObject(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function base64UrlEncode(buffer: Buffer): string {
    return buffer.toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function normalizeBase64Url(input: string): string {
    const padLength = (4 - (input.length % 4)) % 4;
    return input.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat(padLength);
}

function base64UrlDecode(input: string, part: 'header' | 'payload' | 'signature'): Buffer {
    if (!BASE64URL_REGEXP.test(input)) {
        throw new Error(`JWT: invalid base64url encoding in ${part}.`);
    }
    const normalized = normalizeBase64Url(input);
    const buffer = Buffer.from(normalized, 'base64');
    // Ensure that encoding/decoding round-trips to avoid silent truncation
    if (base64UrlEncode(buffer) !== input.replace(/=+$/, '')) {
        throw new Error(`JWT: malformed base64url segment in ${part}.`);
    }
    return buffer;
}

function getTimestamp(optionsTimestamp?: number): number {
    if (optionsTimestamp !== undefined) {
        if (!Number.isFinite(optionsTimestamp)) {
            throw new Error('JWT: clockTimestamp must be a finite number.');
        }
        return Math.floor(optionsTimestamp);
    }
    return Math.floor(Date.now() / 1000);
}

function normalizeAudience(audience: string | string[]): string[] {
    if (Array.isArray(audience)) {
        const entries = audience.map(value => {
            if (typeof value !== 'string' || value.length === 0) {
                throw new Error('Audience must be a non-empty string.');
            }
            return value;
        });
        if (entries.length === 0) {
            throw new Error('Audience array must not be empty.');
        }
        return entries;
    }
    if (typeof audience !== 'string' || audience.length === 0) {
        throw new Error('Audience must be a non-empty string.');
    }
    return [audience];
}

function assertClaimConsistency<T>(
    claims: Record<string, unknown>,
    key: keyof JwtPayload,
    value: T | undefined
): void {
    if (value === undefined) {
        return;
    }
    const existing = claims[key as string];
    if (existing !== undefined && existing !== value) {
        throw new Error(`JWT: claim \"${String(key)}\" already present with a different value.`);
    }
    claims[key as string] = value as unknown;
}

function assertNumericClaim(claimName: keyof JwtPayload, value: unknown): asserts value is number {
    if (typeof value !== 'number' || !Number.isFinite(value)) {
        throw new Error(`JWT: Claim \"${String(claimName)}\" must be a finite number.`);
    }
}

function assertStringClaim(claimName: keyof JwtPayload, value: unknown): asserts value is string {
    if (typeof value !== 'string' || value.length === 0) {
        throw new Error(`JWT: Claim \"${String(claimName)}\" must be a non-empty string.`);
    }
}

function createSignatureBuffer(algorithm: JwtAlgorithm, secret: string, signingInput: string): Buffer {
    const hashAlgorithm = HASH_ALGORITHMS[algorithm];
    return crypto.createHmac(hashAlgorithm, secret).update(signingInput).digest();
}

export function signJwt(
    payload: Record<string, unknown>,
    options: SignJwtOptions
): string {
    if (!isPlainObject(payload)) {
        throw new Error('JWT: payload must be a plain object.');
    }
    if (!options || typeof options.secret !== 'string' || options.secret.length === 0) {
        throw new Error('JWT: a non-empty secret is required to sign.');
    }
    const algorithm: JwtAlgorithm = options.algorithm ?? 'HS256';
    if (!HASH_ALGORITHMS[algorithm]) {
        throw new Error(`JWT: unsupported signing algorithm: ${String(algorithm)}.`);
    }

    const header: JwtHeader = {
        typ: 'JWT',
        alg: algorithm,
        ...(options.header || {})
    } as JwtHeader;

    if (header.alg !== algorithm) {
        throw new Error('JWT: header algorithm mismatch.');
    }
    if (header.typ !== 'JWT') {
        throw new Error('JWT: header type must be "JWT".');
    }

    const timestamp = getTimestamp(options.clockTimestamp);
    const claims: Record<string, unknown> = { ...payload };

    if (options.issuedAt !== undefined) {
        assertNumericClaim('iat', options.issuedAt);
        assertClaimConsistency(claims, 'iat', Math.floor(options.issuedAt));
    } else if (claims.iat === undefined) {
        claims.iat = timestamp;
    } else {
        assertNumericClaim('iat', claims.iat);
    }

    if (options.expiresIn !== undefined) {
        if (typeof options.expiresIn !== 'number' || !Number.isFinite(options.expiresIn) || options.expiresIn <= 0) {
            throw new Error('JWT: expiresIn must be a positive number of seconds.');
        }
        assertClaimConsistency(claims, 'exp', timestamp + Math.floor(options.expiresIn));
    } else if (claims.exp !== undefined) {
        assertNumericClaim('exp', claims.exp);
    }

    if (options.notBefore !== undefined) {
        if (typeof options.notBefore !== 'number' || !Number.isFinite(options.notBefore)) {
            throw new Error('JWT: notBefore must be a number of seconds.');
        }
        assertClaimConsistency(claims, 'nbf', timestamp + Math.floor(options.notBefore));
    } else if (claims.nbf !== undefined) {
        assertNumericClaim('nbf', claims.nbf);
    }

    if (options.audience !== undefined) {
        const audiences = normalizeAudience(options.audience);
        assertClaimConsistency(claims, 'aud', audiences.length === 1 ? audiences[0] : audiences);
    } else if (claims.aud !== undefined) {
        if (Array.isArray(claims.aud)) {
            claims.aud = normalizeAudience(claims.aud);
        } else {
            assertStringClaim('aud', claims.aud);
        }
    }

    if (options.issuer !== undefined) {
        assertStringClaim('iss', options.issuer);
        assertClaimConsistency(claims, 'iss', options.issuer);
    } else if (claims.iss !== undefined) {
        assertStringClaim('iss', claims.iss);
    }

    if (options.subject !== undefined) {
        assertStringClaim('sub', options.subject);
        assertClaimConsistency(claims, 'sub', options.subject);
    } else if (claims.sub !== undefined) {
        assertStringClaim('sub', claims.sub);
    }

    const encodedHeader = base64UrlEncode(Buffer.from(JSON.stringify(header)));
    const encodedPayload = base64UrlEncode(Buffer.from(JSON.stringify(claims)));
    const signingInput = `${encodedHeader}.${encodedPayload}`;
    const signature = base64UrlEncode(createSignatureBuffer(algorithm, options.secret, signingInput));

    return `${encodedHeader}.${encodedPayload}.${signature}`;
}

export function verifyJwt<T extends Record<string, unknown> = Record<string, unknown>>(
    token: string,
    options: VerifyJwtOptions
): T {
    if (typeof token !== 'string' || token.length === 0) {
        throw new Error('JWT: token must be a non-empty string.');
    }
    if (!options || typeof options.secret !== 'string' || options.secret.length === 0) {
        throw new Error('JWT: a non-empty secret is required to verify.');
    }

    const parts = token.split('.');
    if (parts.length !== 3 || parts.some(part => part.length === 0)) {
        throw new Error('JWT: invalid token structure.');
    }

    const [encodedHeader, encodedPayload, encodedSignature] = parts;
    const normalizedMaxPayloadSize = normalizeMaxPayloadSize(options.maxPayloadSize);
    const allowedClaimsSet = normalizeAllowedClaimsOption(options.allowedClaims);
    const headerBuffer = base64UrlDecode(encodedHeader, 'header');
    let header: JwtHeader;
    try {
        const parsed = JSON.parse(headerBuffer.toString('utf8'));
        if (!isPlainObject(parsed)) {
            throw new Error('JWT: header must be a JSON object.');
        }
        header = parsed as JwtHeader;
    } catch (error) {
        throw new Error('JWT: invalid header JSON.');
    }

    if (header.alg === undefined || typeof header.alg !== 'string') {
        throw new Error('JWT: missing algorithm.');
    }
    if (header.alg.toUpperCase() === 'NONE') {
        throw new Error('JWT: unsigned tokens (alg "none") are not allowed.');
    }

    const algorithm = header.alg.toUpperCase() as JwtAlgorithm;
    if (!HASH_ALGORITHMS[algorithm]) {
        throw new Error(`JWT: unsupported algorithm: ${header.alg}.`);
    }

    if (header.typ !== undefined && header.typ !== 'JWT') {
        throw new Error('JWT: invalid type (typ must be "JWT").');
    }

    if (options.algorithms && !options.algorithms.includes(algorithm)) {
        throw new Error(`JWT: algorithm ${algorithm} is not allowed.`);
    }

    const payloadBuffer = base64UrlDecode(encodedPayload, 'payload');
    if (normalizedMaxPayloadSize !== undefined && payloadBuffer.length > normalizedMaxPayloadSize) {
        throw new Error('JWT: payload exceeds maxPayloadSize.');
    }
    let payload: JwtPayload;
    try {
        const parsed = JSON.parse(payloadBuffer.toString('utf8'));
        if (!isPlainObject(parsed)) {
            throw new Error('JWT: payload must be a JSON object.');
        }
        payload = parsed as JwtPayload;
    } catch (error) {
        throw new Error('JWT: invalid payload JSON.');
    }

    if (allowedClaimsSet) {
        for (const key of Object.keys(payload)) {
            if (STANDARD_CLAIMS.has(key)) {
                continue;
            }
            if (!allowedClaimsSet.has(key)) {
                throw new Error(`JWT: claim "${key}" is not allowed.`);
            }
        }
    }

    const expectedSignature = createSignatureBuffer(algorithm, options.secret, `${encodedHeader}.${encodedPayload}`);
    const providedSignature = base64UrlDecode(encodedSignature, 'signature');

    if (providedSignature.length !== expectedSignature.length) {
        throw new Error('JWT: invalid signature.');
    }
    if (!crypto.timingSafeEqual(providedSignature, expectedSignature)) {
        throw new Error('JWT: invalid signature.');
    }

    validateTemporalClaims(payload, options);
    validateAudienceClaim(payload, options);
    validateIssuerClaim(payload, options);
    validateSubjectClaim(payload, options);

    return payload as T;
}

function normalizeMaxPayloadSize(value?: number): number | undefined {
    if (value === undefined) {
        return undefined;
    }
    if (!Number.isFinite(value) || value <= 0) {
        throw new Error('JWT: maxPayloadSize must be a positive number of bytes.');
    }
    return Math.floor(value);
}

function normalizeAllowedClaimsOption(allowedClaims?: string[]): Set<string> | undefined {
    if (allowedClaims === undefined) {
        return undefined;
    }
    if (!Array.isArray(allowedClaims)) {
        throw new Error('JWT: allowedClaims must be an array of non-empty strings.');
    }
    const set = new Set<string>();
    for (const claim of allowedClaims) {
        if (typeof claim !== 'string') {
            throw new Error('JWT: allowedClaims must be an array of non-empty strings.');
        }
        const trimmed = claim.trim();
        if (trimmed.length === 0) {
            throw new Error('JWT: allowedClaims must be an array of non-empty strings.');
        }
        set.add(trimmed);
    }
    return set;
}

function validateTemporalClaims(payload: JwtPayload, options: VerifyJwtOptions): void {
    const now = getTimestamp(options.clockTimestamp);
    const tolerance = options.clockTolerance ?? 0;
    if (!Number.isFinite(tolerance) || tolerance < 0) {
        throw new Error('JWT: clockTolerance must be a non-negative number.');
    }

    if (payload.exp !== undefined) {
        assertNumericClaim('exp', payload.exp);
        if (now > payload.exp + tolerance) {
            throw new Error('JWT: token expired.');
        }
    }

    if (payload.nbf !== undefined) {
        assertNumericClaim('nbf', payload.nbf);
        if (now + tolerance < payload.nbf) {
            throw new Error('JWT: token not active yet.');
        }
    }

    if (payload.iat !== undefined) {
        assertNumericClaim('iat', payload.iat);
        if (payload.iat - tolerance > now) {
            throw new Error('JWT: token used before issued.');
        }
    }

    if (options.maxAge !== undefined) {
        if (!Number.isFinite(options.maxAge) || options.maxAge <= 0) {
            throw new Error('JWT: maxAge must be a positive number of seconds.');
        }
        if (payload.iat === undefined) {
            throw new Error('JWT: cannot apply maxAge without an "iat" claim.');
        }
        if (now - payload.iat - tolerance > options.maxAge) {
            throw new Error('JWT: token exceeds maxAge.');
        }
    }
}

function validateAudienceClaim(payload: JwtPayload, options: VerifyJwtOptions): void {
    if (payload.aud === undefined && options.audience === undefined) {
        return;
    }

    let tokenAudience: string[];
    if (payload.aud !== undefined) {
        if (Array.isArray(payload.aud)) {
            tokenAudience = normalizeAudience(payload.aud);
        } else {
            assertStringClaim('aud', payload.aud);
            tokenAudience = [payload.aud];
        }
    } else {
        throw new Error('JWT: missing required audience claim.');
    }

    if (options.audience === undefined) {
        return;
    }

    const expectedAudiences = normalizeAudience(options.audience);
    const hasMatch = expectedAudiences.some(expected => tokenAudience.includes(expected));
    if (!hasMatch) {
        throw new Error('JWT: audience mismatch.');
    }
}

function validateIssuerClaim(payload: JwtPayload, options: VerifyJwtOptions): void {
    if (payload.iss === undefined && options.issuer === undefined) {
        return;
    }

    if (payload.iss === undefined) {
        throw new Error('JWT: missing required issuer claim.');
    }
    assertStringClaim('iss', payload.iss);

    if (options.issuer === undefined) {
        return;
    }

    if (Array.isArray(options.issuer)) {
        const allowed = options.issuer.some(value => {
            if (typeof value !== 'string' || value.length === 0) {
                throw new Error('Issuer values must be non-empty strings.');
            }
            return value === payload.iss;
        });
        if (!allowed) {
            throw new Error('JWT: issuer mismatch.');
        }
    } else {
        if (typeof options.issuer !== 'string' || options.issuer.length === 0) {
            throw new Error('JWT: issuer must be a non-empty string.');
        }
        if (options.issuer !== payload.iss) {
            throw new Error('JWT: issuer mismatch.');
        }
    }
}

function validateSubjectClaim(payload: JwtPayload, options: VerifyJwtOptions): void {
    if (payload.sub === undefined && options.subject === undefined) {
        return;
    }

    if (payload.sub === undefined) {
        throw new Error('JWT: missing required subject claim.');
    }
    assertStringClaim('sub', payload.sub);

    if (options.subject === undefined) {
        return;
    }

    if (typeof options.subject !== 'string' || options.subject.length === 0) {
        throw new Error('JWT: subject must be a non-empty string.');
    }

    if (payload.sub !== options.subject) {
        throw new Error('JWT: subject mismatch.');
    }
}

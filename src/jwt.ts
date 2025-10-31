import * as crypto from 'crypto';

export type JwtAlgorithm = 'HS256' | 'HS512';

export interface JwtHeader {
    alg: JwtAlgorithm;
    typ: 'JWT';
    [key: string]: unknown;
}

export type JwtPayload = Record<string, unknown>;

export interface SignJwtOptions {
    algorithm?: JwtAlgorithm;
    header?: Record<string, unknown>;
    expiresIn?: number;
    notBefore?: number;
    issuedAt?: number;
    issuer?: string;
    subject?: string;
    audience?: string | string[];
}

export interface VerifyJwtOptions {
    algorithms?: JwtAlgorithm[];
    clockTolerance?: number;
    maxAge?: number;
    audience?: string | string[];
    issuer?: string | string[];
    subject?: string | string[];
    currentTimestamp?: number;
}

export interface VerifyJwtResult<T extends JwtPayload = JwtPayload> {
    header: JwtHeader;
    payload: T;
}

const SUPPORTED_ALGORITHMS: ReadonlyArray<JwtAlgorithm> = ['HS256', 'HS512'];
const BASE64URL_REGEX = /^[A-Za-z0-9_-]*$/;

function assertSecret(secret: string): void {
    if (typeof secret !== 'string' || secret.length === 0) {
        throw new Error('Secret must be a non-empty string.');
    }
}

function normalizeClockTolerance(tolerance?: number): number {
    if (tolerance === undefined) {
        return 0;
    }
    if (typeof tolerance !== 'number' || !Number.isFinite(tolerance) || tolerance < 0) {
        throw new Error('clockTolerance must be a non-negative number.');
    }
    return tolerance;
}

function normalizeMaxAge(maxAge?: number): number | undefined {
    if (maxAge === undefined) {
        return undefined;
    }
    if (typeof maxAge !== 'number' || !Number.isFinite(maxAge) || maxAge <= 0) {
        throw new Error('maxAge must be a positive number.');
    }
    return maxAge;
}

function base64UrlEncode(input: Buffer | string): string {
    const buffer = typeof input === 'string' ? Buffer.from(input, 'utf8') : input;
    return buffer.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/u, '');
}

function base64UrlDecode(input: string): Buffer {
    if (typeof input !== 'string' || !BASE64URL_REGEX.test(input)) {
        throw new Error('Invalid base64url input.');
    }
    const padLength = (4 - (input.length % 4)) % 4;
    const base64 = input.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat(padLength);
    return Buffer.from(base64, 'base64');
}

function stringifyAndEncode(object: unknown, context: string): string {
    try {
        return base64UrlEncode(JSON.stringify(object));
    } catch (error) {
        throw new Error(`Failed to encode ${context} as JSON.`);
    }
}

function parseJson(text: string, context: string): Record<string, unknown> {
    try {
        const parsed = JSON.parse(text);
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
            throw new Error();
        }
        return parsed as Record<string, unknown>;
    } catch (error) {
        throw new Error(`Invalid JWT ${context}.`);
    }
}

function createSignature(algorithm: JwtAlgorithm, secret: string, signingInput: string): Buffer {
    const digest = algorithm === 'HS256' ? 'sha256' : 'sha512';
    return crypto.createHmac(digest, secret).update(signingInput).digest();
}

function ensureSupportedAlgorithm(algorithm: string): asserts algorithm is JwtAlgorithm {
    if (algorithm === 'none') {
        throw new Error('Unsecured JWTs (alg "none") are not allowed.');
    }
    if (!SUPPORTED_ALGORITHMS.includes(algorithm as JwtAlgorithm)) {
        throw new Error(`Unsupported JWT algorithm: ${algorithm}.`);
    }
}

function normalizeAudience(audience: string | string[]): string | string[] {
    if (Array.isArray(audience)) {
        if (audience.length === 0 || audience.some(item => typeof item !== 'string' || item.length === 0)) {
            throw new Error('Audience array must contain non-empty strings.');
        }
        return [...audience];
    }
    if (typeof audience !== 'string' || audience.length === 0) {
        throw new Error('Audience must be a non-empty string.');
    }
    return audience;
}

function applyStandardClaims(payload: JwtPayload, options: SignJwtOptions): void {
    const timestamp = options.issuedAt ?? (typeof payload.iat === 'number' ? payload.iat : Math.floor(Date.now() / 1000));
    if (options.issuedAt !== undefined) {
        if (typeof options.issuedAt !== 'number' || !Number.isFinite(options.issuedAt)) {
            throw new Error('issuedAt must be a finite number.');
        }
        payload.iat = options.issuedAt;
    } else if (payload.iat === undefined) {
        payload.iat = timestamp;
    } else if (typeof payload.iat !== 'number' || !Number.isFinite(payload.iat)) {
        throw new Error('Claim "iat" must be a finite number.');
    }

    const reference = typeof payload.iat === 'number' ? payload.iat : timestamp;

    if (options.expiresIn !== undefined) {
        if (typeof options.expiresIn !== 'number' || !Number.isFinite(options.expiresIn) || options.expiresIn <= 0) {
            throw new Error('expiresIn must be a positive number.');
        }
        payload.exp = reference + options.expiresIn;
    } else if (payload.exp !== undefined) {
        if (typeof payload.exp !== 'number' || !Number.isFinite(payload.exp)) {
            throw new Error('Claim "exp" must be a finite number.');
        }
    }

    if (options.notBefore !== undefined) {
        if (typeof options.notBefore !== 'number' || !Number.isFinite(options.notBefore)) {
            throw new Error('notBefore must be a finite number.');
        }
        payload.nbf = reference + options.notBefore;
    } else if (payload.nbf !== undefined) {
        if (typeof payload.nbf !== 'number' || !Number.isFinite(payload.nbf)) {
            throw new Error('Claim "nbf" must be a finite number.');
        }
    }

    if (options.issuer !== undefined) {
        if (typeof options.issuer !== 'string' || options.issuer.length === 0) {
            throw new Error('issuer must be a non-empty string.');
        }
        payload.iss = options.issuer;
    } else if (payload.iss !== undefined && (typeof payload.iss !== 'string' || payload.iss.length === 0)) {
        throw new Error('Claim "iss" must be a non-empty string.');
    }

    if (options.subject !== undefined) {
        if (typeof options.subject !== 'string' || options.subject.length === 0) {
            throw new Error('subject must be a non-empty string.');
        }
        payload.sub = options.subject;
    } else if (payload.sub !== undefined && (typeof payload.sub !== 'string' || payload.sub.length === 0)) {
        throw new Error('Claim "sub" must be a non-empty string.');
    }

    if (options.audience !== undefined) {
        payload.aud = normalizeAudience(options.audience);
    } else if (payload.aud !== undefined) {
        if (Array.isArray(payload.aud)) {
            payload.aud = normalizeAudience(payload.aud as string[]);
        } else if (typeof payload.aud === 'string') {
            payload.aud = normalizeAudience(payload.aud);
        } else {
            throw new Error('Claim "aud" must be a string or an array of strings.');
        }
    }
}

export function signJwt<T extends JwtPayload>(payload: T, secret: string, options: SignJwtOptions = {}): string {
    assertSecret(secret);
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
        throw new Error('JWT payload must be a plain object.');
    }

    const algorithm: JwtAlgorithm = options.algorithm ?? 'HS256';
    ensureSupportedAlgorithm(algorithm);

    const header: JwtHeader = {
        alg: algorithm,
        typ: 'JWT',
        ...options.header,
    } as JwtHeader;

    if (header.alg !== algorithm) {
        throw new Error('JWT header cannot override the signing algorithm.');
    }
    header.typ = typeof header.typ === 'string' ? header.typ : 'JWT';

    const payloadCopy: JwtPayload = { ...payload };
    applyStandardClaims(payloadCopy, options);

    const encodedHeader = stringifyAndEncode(header, 'header');
    const encodedPayload = stringifyAndEncode(payloadCopy, 'payload');
    const signingInput = `${encodedHeader}.${encodedPayload}`;
    const signature = createSignature(algorithm, secret, signingInput);
    const encodedSignature = base64UrlEncode(signature);
    return `${encodedHeader}.${encodedPayload}.${encodedSignature}`;
}

function ensureNumericClaim(value: unknown, claim: string): number {
    if (typeof value !== 'number' || !Number.isFinite(value)) {
        throw new Error(`JWT claim "${claim}" must be a finite number.`);
    }
    return value;
}

function normalizeExpectation(value: string | string[] | undefined, label: string): string[] | undefined {
    if (value === undefined) {
        return undefined;
    }
    if (Array.isArray(value)) {
        if (value.length === 0 || value.some(item => typeof item !== 'string' || item.length === 0)) {
            throw new Error(`${label} must contain non-empty strings.`);
        }
        return value;
    }
    if (typeof value !== 'string' || value.length === 0) {
        throw new Error(`${label} must be a non-empty string.`);
    }
    return [value];
}

function matchAudiences(expected: string[] | undefined, actual: string | string[] | undefined): boolean {
    if (!expected) {
        return true;
    }
    if (actual === undefined) {
        return false;
    }
    if (Array.isArray(actual)) {
        const actualSet = new Set(actual);
        return expected.every(value => actualSet.has(value));
    }
    if (typeof actual === 'string') {
        return expected.every(value => value === actual);
    }
    return false;
}

export function verifyJwt<T extends JwtPayload = JwtPayload>(token: string, secret: string, options: VerifyJwtOptions = {}): VerifyJwtResult<T> {
    assertSecret(secret);
    if (typeof token !== 'string' || token.trim().length === 0) {
        throw new Error('JWT must be a non-empty string.');
    }

    const parts = token.split('.');
    if (parts.length !== 3) {
        throw new Error('JWT must consist of three parts separated by dots.');
    }

    const [encodedHeader, encodedPayload, encodedSignature] = parts;
    if (!encodedHeader || !encodedPayload || !encodedSignature) {
        throw new Error('JWT parts cannot be empty.');
    }

    const headerJson = base64UrlDecode(encodedHeader).toString('utf8');
    const header = parseJson(headerJson, 'header') as JwtHeader;

    if (typeof header.alg !== 'string') {
        throw new Error('JWT header is missing a valid "alg" field.');
    }
    ensureSupportedAlgorithm(header.alg);

    const allowedAlgorithms = options.algorithms ?? SUPPORTED_ALGORITHMS;
    if (!allowedAlgorithms.includes(header.alg)) {
        throw new Error(`Algorithm ${header.alg} is not allowed.`);
    }

    const payloadJson = base64UrlDecode(encodedPayload).toString('utf8');
    const payload = parseJson(payloadJson, 'payload') as T;

    const expectedSignature = createSignature(header.alg, secret, `${encodedHeader}.${encodedPayload}`);
    const providedSignature = base64UrlDecode(encodedSignature);
    if (providedSignature.length !== expectedSignature.length) {
        throw new Error('Invalid JWT signature.');
    }
    if (!crypto.timingSafeEqual(providedSignature, expectedSignature)) {
        throw new Error('Invalid JWT signature.');
    }

    const now = options.currentTimestamp ?? Math.floor(Date.now() / 1000);
    const tolerance = normalizeClockTolerance(options.clockTolerance);
    const maxAge = normalizeMaxAge(options.maxAge);

    if (payload.exp !== undefined) {
        const exp = ensureNumericClaim(payload.exp, 'exp');
        if (now > exp + tolerance) {
            throw new Error('JWT has expired.');
        }
    }

    if (payload.nbf !== undefined) {
        const nbf = ensureNumericClaim(payload.nbf, 'nbf');
        if (now + tolerance < nbf) {
            throw new Error('JWT is not valid yet.');
        }
    }

    if (payload.iat !== undefined) {
        const iat = ensureNumericClaim(payload.iat, 'iat');
        if (maxAge !== undefined && now - iat > maxAge + tolerance) {
            throw new Error('JWT has exceeded the allowed maxAge.');
        }
    } else if (maxAge !== undefined) {
        throw new Error('JWT is missing required "iat" claim for maxAge validation.');
    }

    const expectedIssuers = normalizeExpectation(options.issuer, 'issuer');
    if (expectedIssuers) {
        if (payload.iss === undefined || typeof payload.iss !== 'string' || payload.iss.length === 0) {
            throw new Error('JWT issuer does not match the expected value.');
        }
        if (!expectedIssuers.includes(payload.iss)) {
            throw new Error('JWT issuer does not match the expected value.');
        }
    }

    const expectedSubjects = normalizeExpectation(options.subject, 'subject');
    if (expectedSubjects) {
        if (payload.sub === undefined || typeof payload.sub !== 'string' || payload.sub.length === 0) {
            throw new Error('JWT subject does not match the expected value.');
        }
        if (!expectedSubjects.includes(payload.sub)) {
            throw new Error('JWT subject does not match the expected value.');
        }
    }

    const expectedAudience = normalizeExpectation(options.audience, 'audience');
    if (expectedAudience && !matchAudiences(expectedAudience, payload.aud as string | string[] | undefined)) {
        throw new Error('JWT audience does not match the expected value.');
    }

    return { header, payload };
}

export const base64Url = {
    encode: base64UrlEncode,
    decode: base64UrlDecode,
};


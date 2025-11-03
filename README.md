# Advanced Token Manager

---

## Links

- [English Version](./README.md)
- [Portuguese Version](./README_pt.md)

## Overview

**AdvancedTokenManager** is a TypeScript library to generate and validate secure tokens with advanced obfuscation. Ideal for applications requiring data security, such as authentication, information signing, or secure storage.

---

## Features

### Performance

Performance tests show that token generation and validation are extremely fast (average result of 1,000 iterations performed 10 times). These tests were conducted on an Apple M1 processor.
- Average memory usage during token generation: **0.9766 MB**.
- Average memory usage during token validation: **0.9842 MB**.
- Average time for `generateToken` is **0.002953 ms**.
- Average time for `validateToken` is **0.002344 ms**.

### Security

- Uses HMAC with a private secret to ensure token integrity.
- Adds a random salt to each token, making decryption difficult.

### Flexibility

- Supports various hash algorithms (`sha256` by default, `sha512`).
- Customizable `secret` and `salts` configuration.

### Easy Integration

- Automatic generation of `secret` and `salts` if needed.
- Supports extracting original data from valid tokens.

---

## Installation

```bash
npm i hash-token
```

---

## Examples

### Manual Configuration

```typescript
import AdvancedTokenManager from 'hash-token';

const secretKey = process.env.SECRET_KEY || "secure-key";
const salts = process.env.SALTS?.split(',') || ["salt1", "salt2", "salt3"];

const tokenManager = new AdvancedTokenManager(secretKey, salts);

const token = tokenManager.generateToken("sensitive-data");
console.log("Generated Token:", token);

const validatedData = tokenManager.validateToken(token);
console.log(validatedData ? "Valid Token:" : "Invalid Token");
```

### Automatic Generation (Use with Caution)

```typescript
import AdvancedTokenManager from 'hash-token';

const tokenManager = new AdvancedTokenManager();

const config = tokenManager.getConfig();
console.warn("⚠️ Save these values securely:");
console.log("SECRET:", config.secret);
console.log("SALTS:", config.salts.join(','));

const token = tokenManager.generateToken("auto-generated-data");
console.log("Generated Token:", token);

const validatedData = tokenManager.validateToken(token);
console.log(validatedData ? "Valid Token:" : "Invalid Token");
```

**Important:** Save the `secret` and `salts` generated automatically to ensure consistent behavior.

### Forced Salt Index Usage

You can force the use of a specific salt index when generating tokens for added control and predictability.

```typescript
import AdvancedTokenManager from 'hash-token';

const tokenManager = new AdvancedTokenManager('secure-key', ['salt1', 'salt2', 'salt3']);

const token = tokenManager.generateToken('sensitive-data', 1);
console.log('Generated Token:', token);

const validatedData = tokenManager.validateToken(token);
console.log(validatedData ? 'Valid Token:' : 'Invalid Token');
```

**Note:** Ensure that the forced salt index exists, or an error will be thrown.

---

### AdvancedTokenManager options

Pass an optional configuration object as the last constructor argument to fine-tune behaviour:

```typescript
import AdvancedTokenManager from 'hash-token';

const manager = new AdvancedTokenManager('secure-key', ['salt1', 'salt2'], 'sha256', true, false, {
    logger: { warn: message => myLogger.warn(message) },
    jwtDefaultAlgorithms: ['HS256'],
    defaultSecretLength: 48,
    defaultSaltCount: 12,
    defaultSaltLength: 24
});
```

| Option | Type | Requirement | Description |
| --- | --- | --- | --- |
| `logger.warn` | `(message: string) => void` | optional | Redirects warning messages (defaults to `console`). |
| `logger.error` | `(message: string) => void` | optional | Handles validation errors (defaults to `console.error`). |
| `jwtDefaultAlgorithms` | `JwtAlgorithm[]` | optional | Algorithms enforced automatically when `validateJwt` is called without `algorithms`. |
| `defaultSecretLength` | `number` | ≥ 16 | Length used when auto-generating secrets. |
| `defaultSaltCount` | `number` | ≥ 2 | Amount of salts generated when none are provided. |
| `defaultSaltLength` | `number` | ≥ 1 | Length of each generated salt string. |
| `throwOnValidationFailure` | `boolean` | optional | Throws instead of returning `null` when `validateToken` fails. |
| `jwtMaxPayloadSize` | `number` | > 0 | Maximum payload size (bytes) enforced during `validateJwt`. |
| `jwtAllowedClaims` | `string[]` | optional | Whitelist of additional claims allowed beyond the standard ones. |

Need stricter token handling for debugging? Pass `throwOnFailure` per call:

```typescript
try {
    tokenManager.validateToken(token, { throwOnFailure: true });
} catch (error) {
    auditLogger.error('Suspicious token rejected', error);
}
```

---

## JWT (native, dependency-free)

`hash-token` ships with a zero-dependency JSON Web Token implementation that relies on Node.js `crypto` only. It protects against common JWT pitfalls, enforces strict validation and integrates with the existing `AdvancedTokenManager` class.

Security tips for JWT usage:
- Pin algorithms in production with `algorithms: ['HS256']` or `['HS512']` when verifying.
- Consider a small `clockTolerance` (e.g., 5–30s) in distributed systems.
- `notBefore` in `signJwt` is a relative offset (seconds) from the current time.

### Core helpers

| Helper | Description |
| --- | --- |
| `signJwt(payload, options)` | Builds a signed JWT string using HMAC (HS256 or HS512). |
| `verifyJwt(token, options)` | Validates structure, signature and claims before returning the payload. |

### Signing options

| Option | Type | Default | Notes |
| --- | --- | --- | --- |
| `secret` | `string` | — | Required. HMAC secret used to sign the token. |
| `algorithm` | `'HS256' \| 'HS512'` | `HS256` | Chooses the HMAC digest. |
| `expiresIn` | `number` (seconds) | — | Adds an `exp` claim relative to the current time. |
| `notBefore` | `number` (seconds) | — | Adds an `nbf` claim relative to the current time. |
| `issuedAt` | `number` (epoch seconds) | now | Overrides the automatic `iat`. |
| `issuer` | `string` | — | Ensures a consistent `iss` claim. |
| `audience` | `string \| string[]` | — | Accepts a single or multiple audiences. |
| `subject` | `string` | — | Sets the `sub` claim. |

### Verification options

| Option | Type | Default | Notes |
| --- | --- | --- | --- |
| `secret` | `string` | — | Required. Must match the signing secret. |
| `algorithms` | `JwtAlgorithm[]` | any supported | Restricts which algorithms are allowed. |
| `clockTolerance` | `number` (seconds) | `0` | Accepts small clock skews for `exp`, `nbf`, `iat`. |
| `maxAge` | `number` (seconds) | — | Caps the lifetime counted from `iat`. |
| `issuer` | `string \| string[]` | — | Expected issuers. Missing or mismatched claims reject the token. |
| `audience` | `string \| string[]` | — | Expected audiences. |
| `subject` | `string` | — | Expected subject. |
| `maxPayloadSize` | `number` (bytes) | — | Rejects tokens whose payload exceeds the configured byte length. |
| `allowedClaims` | `string[]` | — | Restricts additional claims to the provided whitelist (standard claims remain accepted). |

### Usage examples

```typescript
import { signJwt, verifyJwt } from 'hash-token';

const secret = 'rotate-me';

const token = signJwt(
    { userId: 'u-123', role: 'admin' },
    { secret, algorithm: 'HS512', expiresIn: 300 }
);

const payload = verifyJwt(token, {
    secret,
    algorithms: ['HS512'],
    audience: 'dashboard'
});

console.log(payload);
```

For end-to-end samples, check the new scripts under [`examples/`](./examples):

- [`sign-verify.ts`](./examples/sign-verify.ts)
- [`with-claims.ts`](./examples/with-claims.ts)
- [`manager-integration.ts`](./examples/manager-integration.ts)

---

## Tests

Use Jest to test functionality under various scenarios, such as altered tokens or invalid salts.

```bash
npm install --save-dev jest @types/jest ts-jest
npm test
```

---

## License

This project is licensed under the [MIT License](https://opensource.org/licenses/MIT).

---

## Contact

For questions or suggestions, please open an issue on [GitHub](https://github.com/dnettoRaw/hashToken/issues).

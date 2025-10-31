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

### JWT (native, dependency-free)

- Native HS256/HS512 signing built on Node.js `crypto` (no extra packages).
- Base64URL encoding without padding plus strong validation for header and payload formats.
- Optional claim helpers such as `expiresIn`, `notBefore`, `issuer`, `audience`, and `subject`.
- Works standalone or through `AdvancedTokenManager.generateJwt()` / `validateJwt()`.

#### Signing options

| Option | Type | Description |
| --- | --- | --- |
| `algorithm` | `'HS256' \| 'HS512'` | Selects the HMAC digest. Defaults to HS256. |
| `expiresIn` | `number` (seconds) | Adds `exp` relative to `iat`. Must be positive. |
| `notBefore` | `number` (seconds) | Adds `nbf` relative to `iat` to delay validity. |
| `issuedAt` | `number` (seconds) | Sets the `iat` claim. Defaults to `Date.now()/1000`. |
| `issuer` | `string` | Sets `iss`. Useful to scope who created the token. |
| `subject` | `string` | Sets `sub`. Ideal for user identifiers. |
| `audience` | `string \| string[]` | Sets `aud` for single or multiple audiences. |

#### Verification options

| Option | Type | Description |
| --- | --- | --- |
| `algorithms` | `('HS256' \| 'HS512')[]` | Restrict accepted algorithms (default allows both). |
| `clockTolerance` | `number` (seconds) | Accepts small clock drift for `exp`/`nbf` checks. |
| `maxAge` | `number` (seconds) | Ensures `iat` is recent enough. Requires `iat`. |
| `issuer` | `string \| string[]` | Expected `iss` claim(s). |
| `audience` | `string \| string[]` | Expected `aud` claim(s). |
| `subject` | `string \| string[]` | Expected `sub` claim. |
| `currentTimestamp` | `number` (seconds) | Override `Date.now()/1000` for deterministic validation. |

#### Quick example

```typescript
import { signJwt, verifyJwt } from 'hash-token';

const secret = process.env.JWT_SECRET ?? 'super-secret';

const token = signJwt(
  { userId: 'u-123', scope: ['profile:read'] },
  secret,
  { expiresIn: 900, issuer: 'auth-service', audience: ['web'] }
);

const { payload } = verifyJwt(token, secret, { audience: 'web', issuer: 'auth-service' });
console.log(payload.userId); // "u-123"
```

`AdvancedTokenManager` exposes the same functionality:

```typescript
const manager = new AdvancedTokenManager('secret', ['salt-a', 'salt-b']);
const jwt = manager.generateJwt({ workspaceId: '42' }, { expiresIn: 300 });
const result = manager.validateJwt(jwt, { audience: 'dashboard' });
console.log(result.payload.workspaceId);
```

More runnable snippets live in [`examples/`](./examples).

#### Security tips

- Always keep the JWT secret private and rotate it periodically.
- Prefer `clockTolerance` ≤ 30 seconds to handle skew without hiding issues.
- Enforce `issuer`, `audience`, and `subject` whenever you can to avoid replay across services.

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

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
